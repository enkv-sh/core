package nativeprocess

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/format"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	observer "enkv.sh/core/testsupport/nativeprocess"
	"enkv.sh/sdk/artifact"
	artifactbuild "enkv.sh/sdk/artifact/build"
)

func nativeManifestBuild(t *testing.T, directory, command, output string) artifact.LocalPlugin {
	t.Helper()
	for _, key := range []string{"GOFLAGS", "GOEXPERIMENT", "GCCGO", "CC", "CXX", "CGO_CFLAGS", "CGO_CPPFLAGS", "CGO_CXXFLAGS", "CGO_FFLAGS", "CGO_LDFLAGS", "GOTOOLDIR", "GOCACHEPROG", "GOFIPS140", "GODEBUG"} {
		t.Setenv(key, "")
	}
	root := nativeRepository(t)
	workspace := nativePluginWorkspace(t, []string{nativeGeneratedSourcePath(root, "sdk/artifact"), nativeGeneratedSourcePath(root, "sdk/manifest-generator"), nativeGeneratedSourcePath(root, "protocols/manifest-generator"), nativeGeneratedSourcePath(root, "plugins/manifest-generators/generic-json"), directory})
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	descriptorPath := "plugin.json"
	if command != "." {
		descriptorPath = filepath.Join(command, "plugin.json")
	}
	marker, err := artifactbuild.Run(ctx, artifactbuild.Config{Directory: directory, Descriptor: descriptorPath, Command: command, Output: output, Workspace: workspace})
	if err != nil {
		t.Fatal("public manifest build failed", err)
	}
	metadata, err := artifact.VerifyBuild(ctx, output)
	if err != nil || metadata.Role != "manifest-generator" || metadata.Family == nil {
		t.Fatal("published manifest build differs", err)
	}
	identity, err := metadata.Identity()
	if err != nil || marker.Artifact != identity {
		t.Fatal("published manifest identity differs", err)
	}
	t.Logf("native manifest build version=%s module=%s artifact=%s executable=%s", metadata.Version, metadata.MainModule, marker.Artifact, metadata.Executable.SHA256)
	return artifact.LocalPlugin{Name: "generic-json", Directory: output}
}

func nativeManifestProductionBuild(t *testing.T) artifact.LocalPlugin {
	t.Helper()
	root := nativeRepository(t)
	return nativeManifestBuild(t, nativeGeneratedSourcePath(root, "plugins/manifest-generators/generic-json"), "./cmd/enkv-manifest-generic-json", filepath.Join(nativeGeneratedPrivateDirectory(t), "manifest-build"))
}

func nativeManifestAuthorBuild(t *testing.T, output, marker, version string, wrong bool) {
	t.Helper()
	directory := t.TempDir()
	module := "module example.test/manifest-author\n\ngo 1.27.0\n\nrequire (\n enkv.sh/sdk/manifest-generator v0.1.1\n enkv.sh/sdk/protocols/manifest-generator v0.1.1\n enkv.sh/plugins/manifest-generators/generic-json v0.1.1\n)\n"
	source := fmt.Sprintf(`package main
import (
 "bytes"
 "context"
 _ "embed"
 "encoding/json"
 "os"
 "enkv.sh/plugins/manifest-generators/generic-json/execution"
 genericjson "enkv.sh/plugins/manifest-generators/generic-json"
 manifest "enkv.sh/sdk/manifest-generator"
 "enkv.sh/sdk/manifest-generator/native"
)
//go:embed plugin.json
var descriptor []byte
func main(){implementation,err:=execution.NewImplementation(descriptor);if err!=nil{os.Exit(2)}
 implementation.Render=func(ctx context.Context,view manifest.View)manifest.Result{
 result:=genericjson.Render(ctx,view)
 if result.Failure!="" {return result}
 marker:="invoked"
 if %t { prefix:=[]byte("\"target_recipient_id\": \"");at:=bytes.Index(result.Artifact,prefix)+len(prefix);if at<len(prefix)||at>=len(result.Artifact){clear(result.Artifact);return manifest.Result{Failure:manifest.InvalidResult}};if result.Artifact[at]=='f'{result.Artifact[at]='e'}else{result.Artifact[at]='f'};if !json.Valid(result.Artifact){clear(result.Artifact);return manifest.Result{Failure:manifest.InvalidResult}};marker="wrong-valid" }
 if err:=os.WriteFile(%s,[]byte(marker),0600);err!=nil{clear(result.Artifact);return manifest.Result{Failure:manifest.InvalidResult}}
 return result
}
 os.Exit(native.Main(implementation))}
`, wrong, strconv.Quote(marker))
	formatted, err := format.Source([]byte(source))
	if err != nil {
		t.Fatal("independent manifest main syntax differs", err)
	}
	license, err := os.ReadFile(filepath.Join(nativeGeneratedSourcePath(nativeRepository(t), "sdk/manifest-generator"), "LICENSE"))
	if err != nil {
		t.Fatal(err)
	}
	descriptor, _, err := artifact.ReadDescriptor(t.Context(), filepath.Join(nativeGeneratedSourcePath(nativeRepository(t), "plugins/manifest-generators/generic-json"), "cmd/enkv-manifest-generic-json/plugin.json"))
	if err != nil {
		t.Fatal(err)
	}
	descriptor.Version = version
	descriptorBody, err := artifact.EncodeDescriptor(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{"go.mod": []byte(module), "main.go": formatted, "LICENSE": license, "plugin.json": descriptorBody} {
		if err := os.WriteFile(filepath.Join(directory, name), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	nativeManifestBuild(t, directory, ".", output)
}

// full_only: false
func TestPublicNativeManifestUsesIndependentCompatibleBuildWithFrozenCLI(t *testing.T) {
	t.Setenv("CLOUDFLARE_API_TOKEN", "")
	cli, _ := workflowExecutables(t)
	before, err := artifact.ExecutableIdentity(t.Context(), cli)
	if err != nil {
		t.Fatal(err)
	}
	build := nativeManifestProductionBuild(t)
	plugins := newNativePluginFixture(t, build)
	s := newWorkflowServer(t, "aws", false)
	s.childLimit = 8
	s.requestLimit = 8 * workflowChildRequestLimit
	f := nativeMaterializationSetup(t, s, cli, nil)
	children := slices.Clone(f.children)
	target := hex.EncodeToString(f.pair.descriptor.AuthorityRecipientID[:])
	expected := nativeManifestExpected(t, f, nil, "", "", "", target, "current-authority", "exact-names", "", []string{"PLAIN"}, nil, map[string]string{"PLAIN": "public #selected"})
	images := nativePublicationImages(t, f.source, filepath.Join(filepath.Dir(f.source), f.pair.reference))
	_, head := workflowHead(t, s)
	objects := s.objectCount()
	destination := filepath.Join(t.TempDir(), "manifest.json")
	first := nativeManifestRun(t, s, cli, plugins, f.source, "json", destination, observer.Policy{}, "--name", "PLAIN")
	nativeManifestInstalled(t, first, destination, expected)
	children = append(children, first)
	a, err := artifact.VerifyBuild(t.Context(), build.Directory)
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "author-invoked")
	nativeManifestAuthorBuild(t, build.Directory, marker, "2.0.0", false)
	b, err := artifact.VerifyBuild(t.Context(), build.Directory)
	if err != nil || b.MainModule != "example.test/manifest-author" || a.Executable == b.Executable {
		t.Fatal("independent update did not replace actual build", err)
	}
	second := nativeManifestRun(t, s, cli, plugins, f.source, "json", destination, observer.Policy{}, "--name", "PLAIN")
	nativeManifestInstalled(t, second, destination, expected)
	children = append(children, second)
	for _, row := range []struct {
		child    workflowChild
		metadata artifact.Metadata
	}{{first, a}, {second, b}} {
		identity, err := row.metadata.Identity()
		if err != nil {
			t.Fatal(err)
		}
		facts, err := row.metadata.ExecutionFacts()
		if err != nil {
			t.Fatal(err)
		}
		result := nativeManifestResult(t, row.child)
		var selected struct {
			Artifact   string `json:"artifact_id"`
			Descriptor string `json:"descriptor_id"`
			Executor   string `json:"executor_id"`
			Contract   string `json:"artifact_contract_id"`
			Dependency string `json:"dependency_manifest_id"`
			Digest     string `json:"artifact_sha256"`
			Length     uint64 `json:"artifact_length"`
		}
		if result.Issuance.Payload == nil || json.Unmarshal(result.Issuance.Payload.RendererFacts, &selected) != nil || selected.Artifact != identity.String() || selected.Descriptor != facts.DescriptorID.String() || selected.Executor != facts.ExecutorID.String() || selected.Contract != facts.ArtifactContractID.String() || selected.Dependency != facts.DependencyManifestID.String() || selected.Digest != row.metadata.Executable.SHA256.String() || selected.Length != row.metadata.Executable.Length {
			t.Fatal("native manifest invocation did not retain exact A or B renderer support")
		}
	}
	if body, err := os.ReadFile(marker); err != nil || string(body) != "invoked" {
		t.Fatal("independent author executable did not run", err)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	compared := workflowRunEnvironment(t, s, cli, "reader", observer.Policy{NoKMS: true}, nil, plugins.Environment(t, f.source), "plan", "--trusted", f.source, "--trusted-format", "json", "--json")
	children = append(children, compared)
	workflowGETOnly(t, compared)
	comparison := workflowResult(t, compared, "success")
	if comparison.Payload.Verdict != "match" || !comparison.Payload.DiagnosticsComplete {
		t.Fatal("comparison failed without renderer execution", compared.code, compared.summary)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("comparison executed renderer", err)
	}
	nativeManifestAuthorBuild(t, build.Directory, marker, "3.0.0", true)
	wrong := nativeManifestRun(t, s, cli, plugins, f.source, "json", destination, observer.Policy{}, "--name", "PLAIN")
	children = append(children, wrong)
	result := nativeManifestResult(t, wrong)
	expectedWrong := expected
	const targetPrefix = `"target_recipient_id": "`
	at := strings.Index(expectedWrong, targetPrefix) + len(targetPrefix)
	if at < len(targetPrefix) || at >= len(expectedWrong) {
		t.Fatal("independent expected manifest target unavailable")
	}
	changed := []byte(expectedWrong)
	if changed[at] == 'f' {
		changed[at] = 'e'
	} else {
		changed[at] = 'f'
	}
	expectedWrong = string(changed)
	nativeManifestDelivered(t, wrong, destination, expectedWrong)
	var artifactBody struct {
		Target string `json:"target_recipient_id"`
	}
	if json.Unmarshal(changed, &artifactBody) != nil || artifactBody.Target == target || expectedWrong == expected || result.Issuance.Target != target || !bytes.Equal(result.Issuance.Observation, nativeManifestResult(t, first).Issuance.Observation) {
		t.Fatal("independent consumer did not detect the semantic target mismatch")
	}

	if body, err := os.ReadFile(marker); err != nil || string(body) != "wrong-valid" {
		t.Fatal("wrong author build did not emit valid JSON", err)
	}
	after, err := artifact.ExecutableIdentity(t.Context(), cli)
	if err != nil || before != after {
		t.Fatal("plugin update changed frozen CLI", err)
	}
	nativePublicationUnchanged(t, images)
	_, next := workflowHead(t, s)
	if !reflect.DeepEqual(head, next) || objects != s.objectCount() {
		t.Fatal("manifest or comparison changed selected state")
	}
	nativeMaterializationJoined(t, children, 7)
	t.Logf("frozen manifest CLI=%s A=%s B=%s independent_module=%s", before.SHA256, a.Executable.SHA256, b.Executable.SHA256, b.MainModule)
}

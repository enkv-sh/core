package nativeprocess

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/format"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"syscall"
	"testing"
	"time"

	"enkv.sh/core/contract"
	observer "enkv.sh/core/testsupport/nativeprocess"
	"enkv.sh/sdk/artifact"
	artifactbuild "enkv.sh/sdk/artifact/build"
	"enkv.sh/sdk/artifact/credentialroute"
	protocol "enkv.sh/sdk/protocols/generator"
)

type nativeGeneratedPluginInvocation struct {
	Build       string
	PID         int
	Command     protocol.Command
	SDKReturned bool
}

// This literal uses the generic intent field order and independent SHA-256
// identities. The author owns its subject settings and resource contract.
func nativeGeneratedPluginIntent() []byte {
	config := sha256.Sum256([]byte("example/native-generator-config/v1"))
	resource := sha256.Sum256([]byte("example/native-generator-resource/v1"))
	settings := []byte(`{"subject":"` + nativeGeneratedAccountA + `"}`)
	body := binary.BigEndian.AppendUint16(nil, 1)
	body = append(body, config[:]...)
	body = append(body, protocol.LifecycleManaged)
	body = append(body, resource[:]...)
	body = binary.BigEndian.AppendUint32(body, uint32(len(settings)))
	return append(body, settings...)
}

func nativeGeneratedPluginDigest(label string, body []byte) protocol.ID {
	preimage := binary.BigEndian.AppendUint32([]byte("ENKV/GENERATOR/v1/"+label+"\x00"), uint32(len(body)))
	return sha256.Sum256(append(preimage, body...))
}

func nativeGeneratedPluginBuild(t *testing.T, directory, output, markerPath, label, version string) artifact.Metadata {
	t.Helper()
	for _, key := range []string{"GOFLAGS", "GOEXPERIMENT", "GCCGO", "CC", "CXX", "CGO_CFLAGS", "CGO_CPPFLAGS", "CGO_CXXFLAGS", "CGO_FFLAGS", "CGO_LDFLAGS", "GOTOOLDIR", "GOCACHEPROG", "GOFIPS140", "GODEBUG"} {
		t.Setenv(key, "")
	}
	config := artifact.Hash([]byte("example/native-generator-config/v1"))
	route := credentialroute.Route{Schema: credentialroute.Schema, ContractID: sha256.Sum256([]byte("example/native-generator-credentials/v1")), Mode: credentialroute.ModeEnvironment, Names: []string{"CLOUDFLARE_API_TOKEN"}}
	routeBytes, err := credentialroute.Encode(route)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := artifact.Descriptor{Schema: artifact.DescriptorSchema, Name: "cloudflare-account-token", Role: "generator", Version: version, Wire: artifact.Contract{Kind: "wire", Identity: artifact.Digest(protocol.ProtocolID()).String(), Version: uint32(protocol.Version)}, Generator: &artifact.GeneratorDeclaration{ConfigContractID: config, CredentialRoute: routeBytes}}
	descriptorBytes, err := artifact.EncodeDescriptor(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	source := fmt.Sprintf(`package main
import (
 "bytes"
 "context"
 "crypto/sha256"
 _ "embed"
 "encoding/json"
 "errors"
 "io"
 "os"
 "time"
 "enkv.sh/sdk/generator"
 protocol "enkv.sh/sdk/protocols/generator"
)
//go:embed plugin.json
var descriptorBytes []byte
var entered bool
type invocation struct { Build string; PID int; Command protocol.Command; SDKReturned bool }
func record(command *protocol.Command) (result error) {
 file,err:=os.OpenFile(%s,os.O_CREATE|os.O_RDWR,0600);if err!=nil{return err}
 defer func(){result=errors.Join(result,file.Close())}()
 info,err:=file.Stat();if err!=nil||!info.Mode().IsRegular()||info.Mode().Perm()!=0600||info.Size()>8192{return errors.New("marker bounds")}
 body,err:=io.ReadAll(io.LimitReader(file,8193));if err!=nil||len(body)>8192{return errors.New("marker read")}
 var rows []invocation
 if len(body)>0&&json.Unmarshal(body,&rows)!=nil{return errors.New("marker image")}
 if command!=nil {if len(rows)>=2{return errors.New("fixed attempt budget")};rows=append(rows,invocation{Build:%s,PID:os.Getpid(),Command:*command})
 } else {if len(rows)==0||len(rows)>2||rows[len(rows)-1].PID!=os.Getpid()||rows[len(rows)-1].SDKReturned{return errors.New("SDK terminal")};rows[len(rows)-1].SDKReturned=true}
 body,err=json.Marshal(rows);if err!=nil||len(body)>8192{return errors.New("marker encoding")}
 if err=file.Truncate(0);err!=nil{return err};if _,err=file.Seek(0,0);err!=nil{return err}
 n,err:=file.Write(body);if err!=nil||n!=len(body){return errors.Join(err,io.ErrShortWrite)}
 return file.Sync()
}
func execute(ctx context.Context, invocation generator.Invocation)(protocol.SafeFacts,[]byte,error){
 command:=invocation.Command
 refuse:=func()(protocol.SafeFacts,[]byte,error){return protocol.SafeFacts{},nil,errors.New("exact command refused")}
 if ctx.Err()!=nil||!time.UnixMilli(int64(command.DeadlineUnixMillis)).After(time.Now())||command.Action!=protocol.ActionCreate||len(command.OriginalFacts)!=0||
 !bytes.Equal(command.Intent,[]byte(%s))||len(invocation.Inputs)!=1||invocation.Inputs[0].Name!="CLOUDFLARE_API_TOKEN"||!invocation.Inputs[0].Present||!bytes.Equal(invocation.Inputs[0].Value,[]byte(%s)){return refuse()}
 for _,id:=range []protocol.ID{command.DomainID,command.OperationID,command.RequestIdentityDigest,command.PlanGraphID,command.LineageID,command.AttemptID,command.TransmissionID,command.ResultID,command.ResultContractID,command.DescriptorID,command.ExecutorID,command.RequestDigest,command.IntentDigest,command.CredentialRouteID}{if id.IsZero(){return refuse()}}
 if err:=record(&command);err!=nil{return protocol.SafeFacts{},nil,err};entered=true
 return command.NewFacts(protocol.DispositionUnknown,protocol.ReasonRejected),nil,nil
}
func main(){
 config:=protocol.ID(sha256.Sum256([]byte("example/native-generator-config/v1")))
 binding,err:=generator.Bind(descriptorBytes,config);if err!=nil{os.Exit(20)}
 resource:=sha256.Sum256([]byte("example/native-generator-resource/v1"))
 canonical:=[]byte(%s)
 normalize:=func(_ context.Context,r protocol.NormalizeRequest)(protocol.Intent,error){var v map[string]string;decoder:=json.NewDecoder(bytes.NewReader(r.Settings));decoder.DisallowUnknownFields();if decoder.Decode(&v)!=nil||decoder.Decode(new(any))!=io.EOF||len(v)!=1||v["subject"]==""{return protocol.Intent{},errors.New("settings")};settings,err:=json.Marshal(v);return protocol.Intent{Schema:protocol.Schema,ConfigContractID:config,LifecycleMode:protocol.LifecycleManaged,ResourceContractID:resource,Settings:settings},err}
 implementation:=generator.Implementation{Binding:binding,Normalize:normalize,ValidateCanonical:func(_ context.Context,intent protocol.Intent)error{if intent.ConfigContractID!=config||intent.ResourceContractID!=resource||intent.LifecycleMode!=protocol.LifecycleManaged||!bytes.Equal(intent.Settings,canonical){return errors.New("canonical settings")};return nil},CheckRetirementCompatibility:func(context.Context,protocol.RetirementCompatibilityRequest)(bool,error){return false,nil},Create:execute,Retire:func(context.Context,generator.Invocation)(protocol.SafeFacts,error){return protocol.SafeFacts{},errors.New("retirement refused")}}
 code:=generator.Main(implementation);if code==0&&entered{if record(nil)!=nil{code=97}};os.Exit(code)
}
`, strconv.Quote(markerPath), strconv.Quote(label), strconv.Quote(string(nativeGeneratedPluginIntent())), strconv.Quote(nativeGeneratedBearerA), strconv.Quote(`{"subject":"`+nativeGeneratedAccountA+`"}`))
	formatted, err := format.Source([]byte(source))
	if err != nil {
		t.Fatal("independent generator main syntax differs", err)
	}
	root := nativeRepository(t)
	license, err := os.ReadFile(filepath.Join(nativeGeneratedSourcePath(root, "sdk/generator"), "LICENSE"))
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{"go.mod": []byte("module example.test/generator-author\n\ngo 1.27.0\n\nrequire (\n enkv.sh/sdk/artifact v0.1.0\n enkv.sh/sdk/generator v0.1.0\n enkv.sh/sdk/protocols/generator v0.1.0\n)\n"), "main.go": formatted, "plugin.json": descriptorBytes, "LICENSE": license} {
		if err := os.WriteFile(filepath.Join(directory, name), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	workspace := nativePluginWorkspace(t, []string{directory, nativeGeneratedSourcePath(root, "sdk/artifact"), nativeGeneratedSourcePath(root, "sdk/generator"), nativeGeneratedSourcePath(root, "protocols/generator")})
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	marker, err := artifactbuild.Run(ctx, artifactbuild.Config{Directory: directory, Descriptor: "plugin.json", Command: ".", Output: output, Workspace: workspace})
	if err != nil {
		t.Fatal("public independent generator build failed", err)
	}
	metadata, err := artifact.VerifyBuild(ctx, output)
	if err != nil || metadata.MainModule != "example.test/generator-author" || metadata.Command != metadata.MainModule || metadata.Role != "generator" {
		t.Fatal("published independent generator build differs", err)
	}
	identity, err := metadata.Identity()
	if err != nil || marker.Artifact != identity {
		t.Fatal("published independent generator identity differs", err)
	}
	t.Logf("normal independent generator build=%s artifact=%s executable=%s module=%s command=%s", label, identity, metadata.Executable.SHA256, metadata.MainModule, metadata.Command)
	return metadata
}

func nativeGeneratedPluginSource(t *testing.T, s *workflowServer, cli string, plugins nativePluginFixture, scope, name string) (string, workflowChild) {
	t.Helper()
	var source map[string]any
	if json.Unmarshal(workflowSetup(t, s, false), &source) != nil {
		t.Fatal("independent generator state setup unavailable")
	}
	source["domain"].(map[string]any)["name"] = name
	path := filepath.Join(scope, name+".json")
	nativeGeneratedWriteJSON(t, path, source)
	initialized := workflowRunEnvironment(t, s, cli, "init", observer.Policy{}, nil, plugins.Environment(t, path), "init", "--source", path, "--source-format", "json", "--json")
	workflowResult(t, initialized, "success")
	nativeGeneratedReadJSON(t, path, &source)
	source["entries"] = map[string]any{
		"generated": map[string]any{
			"confidentiality": "secret", "recipients": []string{},
			"source": map[string]any{
				"kind": "generated", "plugin": "cloudflare-account-token", "epoch": 0, "retirement": "manual",
				"settings": map[string]any{"subject": nativeGeneratedAccountA},
			},
		},
	}
	nativeGeneratedWriteJSON(t, path, source)
	return path, initialized
}

func nativeGeneratedPluginInvocations(t *testing.T, path, label string, metadata artifact.Metadata, child workflowChild) {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal("independent generator callback did not run", err)
	}
	info, statErr := file.Stat()
	body, readErr := io.ReadAll(io.LimitReader(file, 8193))
	closeErr := file.Close()
	if statErr != nil || readErr != nil || closeErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 8192 || len(body) > 8192 {
		t.Fatal("independent generator marker is not a bounded private image", statErr, readErr, closeErr)
	}
	var rows []nativeGeneratedPluginInvocation
	if json.Unmarshal(body, &rows) != nil || len(rows) != 2 {
		t.Fatal("unknown-work graph did not enter exactly initial and residue Attempts")
	}
	family, err := metadata.GeneratorFacts()
	if err != nil {
		t.Fatal(err)
	}
	route, err := credentialroute.Decode(family.Descriptor.Generator.CredentialRoute)
	if err != nil {
		t.Fatal(err)
	}
	routeID, err := credentialroute.Identity(route)
	if err != nil {
		t.Fatal(err)
	}
	// Decode the exact scalar public effect identities without changing shared
	// lifecycle helpers. Dynamic IDs are compared to each actual SDK command.
	var public struct {
		Operation string `json:"operation_id"`
		Effects   []struct {
			Facts  map[string]json.RawMessage `json:"facts"`
			Target json.RawMessage            `json:"target"`
		} `json:"effects"`
	}
	if json.Unmarshal(child.out, &public) != nil || len(public.Effects) != 2 {
		t.Fatal("independent generator result lost exact entered Attempts")
	}
	seen := map[protocol.ID]bool{}
	for index, row := range rows {
		command := row.Command
		branch := uint8(0)
		if index == 1 {
			branch = 2
		}
		attempt, err := contract.GeneratorAttemptID(contract.ID(command.LineageID), branch)
		if err != nil || command.AttemptID != protocol.ID(attempt) || row.Build != label || row.PID <= 1 || !row.SDKReturned || seen[command.AttemptID] || command.Action != protocol.ActionCreate ||
			command.ExecutorID != protocol.ID(family.ExecutorID) || command.DescriptorID != protocol.ID(family.DescriptorID) || !bytes.Equal(command.Intent, nativeGeneratedPluginIntent()) ||
			command.IntentDigest != nativeGeneratedPluginDigest("intent-v3", command.Intent) || command.RequestDigest.IsZero() || command.CredentialRouteID != protocol.ID(routeID) {
			t.Fatal("independent generator invocation changed exact graph, build, recipe or SDK terminal", index, err)
		}
		seen[command.AttemptID] = true
		if index == 1 && (command.DomainID != rows[0].Command.DomainID || command.OperationID != rows[0].Command.OperationID || command.LineageID != rows[0].Command.LineageID || command.RequestIdentityDigest != rows[0].Command.RequestIdentityDigest || command.PlanGraphID != rows[0].Command.PlanGraphID) {
			t.Fatal("fixed residue successor changed its admitted operation")
		}
		if process, err := os.FindProcess(row.PID); err != nil {
			t.Fatal(err)
		} else {
			signalErr := process.Signal(syscall.Signal(0))
			releaseErr := process.Release()
			if !errors.Is(signalErr, syscall.ESRCH) && !errors.Is(signalErr, os.ErrProcessDone) || releaseErr != nil {
				t.Fatal("normal CLI returned with a surviving native generator", signalErr, releaseErr)
			}
		}
		matched := 0
		for _, effect := range public.Effects {
			text := func(key string) string {
				var value string
				if json.Unmarshal(effect.Facts[key], &value) != nil {
					t.Fatal("public effect lost a scalar fact", key)
				}
				return value
			}
			if text("attempt_id") != hex.EncodeToString(command.AttemptID[:]) {
				continue
			}
			matched++
			for key, id := range map[string]protocol.ID{"operation_id": command.OperationID, "lineage_id": command.LineageID, "attempt_id": command.AttemptID, "transmission_id": command.TransmissionID, "result_id": command.ResultID, "executor_id": command.ExecutorID, "credential_route_id": command.CredentialRouteID, "result_contract_id": command.ResultContractID} {
				if text(key) != hex.EncodeToString(id[:]) {
					t.Fatal("public effect differs from exact independent SDK command", key)
				}
			}
			if text("action") != "create" || text("state") != "closed-with-residue" || text("descriptor_id") != family.DescriptorID.String() || text("config_contract_id") != family.Descriptor.Generator.ConfigContractID.String() || string(effect.Target) != "null" {
				t.Fatal("closed rejected SDK response was upgraded to an owned effect")
			}
		}
		if matched != 1 || public.Operation != hex.EncodeToString(command.OperationID[:]) {
			t.Fatal("public result did not retain one exact effect per SDK command")
		}
	}
}

// full_only: false
// This proves normal admission/execution/update, not provider success. The two domains share
// one application scope; A's unknown operation remains unchanged while B starts.
func TestPublicNativeGeneratedIndependentBuildReplacementWithFrozenCLI(t *testing.T) {
	cli, _ := workflowExecutables(t)
	frozen, err := artifact.ExecutableIdentity(t.Context(), cli)
	if err != nil {
		t.Fatal(err)
	}
	directory := nativeGeneratedPrivateDirectory(t)
	output := filepath.Join(nativeGeneratedPrivateDirectory(t), "generator-build")
	markers := nativeGeneratedPrivateDirectory(t)
	aPath, bPath := filepath.Join(markers, "A.json"), filepath.Join(markers, "B.json")
	a := nativeGeneratedPluginBuild(t, directory, output, aPath, "A", "1.0.0")
	plugins := newNativePluginFixture(t, artifact.LocalPlugin{Name: "cloudflare-account-token", Directory: output})
	scope, err := filepath.EvalSymlinks(nativeGeneratedPrivateDirectory(t))
	if err != nil {
		t.Fatal("independent generator application scope unavailable", err)
	}
	var children []workflowChild
	apply := func(s *workflowServer, name string, metadata artifact.Metadata, marker, label string) string {
		t.Helper()
		s.childLimit, s.objectLimit, s.requestLimit = 4, 512, 4*workflowChildRequestLimit
		source, initialized := nativeGeneratedPluginSource(t, s, cli, plugins, scope, name)
		children = append(children, initialized)
		t.Setenv("CLOUDFLARE_API_TOKEN", nativeGeneratedBearerA)
		pair := workflowReadNamedPair(t, source, name)
		restore := workflowReadOnlyPair(t, source, pair)
		defer restore()
		child := workflowRunEnvironment(t, s, cli, "apply", observer.Policy{}, nil, plugins.Environment(t, source), "apply", "--source", source, "--source-format", "json", "--json")
		children = append(children, child)
		out := nativeGeneratedOutcome(t, child, "effect-unknown", 3)
		if out.EffectSummary != "effect-unknown" || len(out.Current) != 0 {
			t.Fatal("independent generator claimed a successful current value")
		}
		nativeGeneratedPluginInvocations(t, marker, label, metadata, child)
		workflowUnchanged(t, source, pair)
		return source
	}
	serverA := newWorkflowServer(t, "aws", false)
	sourceA := apply(serverA, "author-a", a, aPath, "A")
	_, headA := workflowHead(t, serverA)
	pairA := workflowReadNamedPair(t, sourceA, "author-a")
	b := nativeGeneratedPluginBuild(t, directory, output, bPath, "B", "2.0.0")
	aID, aErr := a.Identity()
	bID, bErr := b.Identity()
	aFamily, aFamilyErr := a.GeneratorFacts()
	bFamily, bFamilyErr := b.GeneratorFacts()
	if aErr != nil || bErr != nil || aFamilyErr != nil || bFamilyErr != nil || aID == bID || a.Executable == b.Executable || aFamily.ExecutorID == bFamily.ExecutorID {
		t.Fatal("source marker replacement did not change actual A/B identities")
	}
	serverB := newWorkflowServer(t, "aws", false)
	sourceB := apply(serverB, "author-b", b, bPath, "B")
	pairB := workflowReadNamedPair(t, sourceB, "author-b")
	if filepath.Dir(sourceA) != filepath.Dir(sourceB) || pairA.descriptor.DomainID.IsZero() || pairB.descriptor.DomainID.IsZero() || pairA.descriptor.DomainID == pairB.descriptor.DomainID {
		t.Fatal("replacement proof lost shared application scope or distinct domains")
	}
	_, afterA := workflowHead(t, serverA)
	workflowUnchanged(t, sourceA, pairA)
	after, err := artifact.ExecutableIdentity(t.Context(), cli)
	if err != nil || frozen != after || !reflect.DeepEqual(headA, afterA) {
		t.Fatal("fresh B invocation changed frozen CLI or A's unresolved state", err)
	}
	nativeMaterializationJoined(t, children, 4)
	t.Logf("normal generator replacement same_application_scope=true distinct_domains=true frozen_cli=%s A=%s B=%s", frozen.SHA256, a.Executable.SHA256, b.Executable.SHA256)
}

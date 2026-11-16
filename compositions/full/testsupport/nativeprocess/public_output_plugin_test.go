package nativeprocess

import (
	"bytes"
	"context"
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

	"enkv.sh/core"
	"enkv.sh/core/contract"
	observer "enkv.sh/core/testsupport/nativeprocess"
	"enkv.sh/sdk/artifact"
	artifactbuild "enkv.sh/sdk/artifact/build"
	"enkv.sh/sdk/artifact/credentialroute"
	"enkv.sh/sdk/output"
	protocol "enkv.sh/sdk/protocols/output"
)

type nativeOutputPluginInvocation struct {
	Build       string
	PID         int
	Preparation output.Preparation
	SDKReturned bool
}

func nativeOutputPluginBuild(t *testing.T, directory, output, markerPath, label, version string) artifact.Metadata {
	t.Helper()
	for _, key := range []string{"GOFLAGS", "GOEXPERIMENT", "GCCGO", "CC", "CXX", "CGO_CFLAGS", "CGO_CPPFLAGS", "CGO_CXXFLAGS", "CGO_FFLAGS", "CGO_LDFLAGS", "GOTOOLDIR", "GOCACHEPROG", "GOFIPS140", "GODEBUG"} {
		t.Setenv(key, "")
	}
	source := fmt.Sprintf(`package main
import (
 "context"
 _ "embed"
 "encoding/json"
 "errors"
 "io"
 "os"
 "enkv.sh/plugins/outputs/aws-secrets-manager/execution"
 "enkv.sh/sdk/output"
 protocol "enkv.sh/sdk/protocols/output"
 "enkv.sh/sdk/artifact/credentialroute"
)
//go:embed plugin.json
var descriptor []byte
type invocation struct {Build string; PID int; Preparation output.Preparation; SDKReturned bool}
type implementation struct {output.Implementation}
func record(facts *output.Preparation)(result error){
 file,err:=os.OpenFile(%s,os.O_CREATE|os.O_RDWR,0600);if err!=nil{return err}
 defer func(){result=errors.Join(result,file.Close())}()
 info,err:=file.Stat();if err!=nil||!info.Mode().IsRegular()||info.Mode().Perm()!=0600||info.Size()>65536{return errors.New("marker bounds")}
 body,err:=io.ReadAll(io.LimitReader(file,65537));if err!=nil||len(body)>65536{return errors.New("marker read")}
 var rows []invocation
 if len(body)>0&&json.Unmarshal(body,&rows)!=nil{return errors.New("marker image")}
 if facts!=nil {rows=append(rows,invocation{Build:%s,PID:os.Getpid(),Preparation:*facts})
 }else{if len(rows)==0||rows[len(rows)-1].PID!=os.Getpid()||rows[len(rows)-1].SDKReturned{return errors.New("SDK terminal")};rows[len(rows)-1].SDKReturned=true}
 body,err=json.Marshal(rows);if err!=nil||len(body)>65536{return errors.New("marker encoding")}
 if err=file.Truncate(0);err!=nil{return err};if _,err=file.Seek(0,0);err!=nil{return err}
 n,err:=file.Write(body);if err!=nil||n!=len(body){return errors.Join(err,io.ErrShortWrite)}
 return file.Sync()
}
func (implementation) Prepare(ctx context.Context,facts output.Preparation,_ protocol.Policy,_ []credentialroute.Input)(output.Prepared,error){
 if err:=ctx.Err();err!=nil{return nil,err};return &prepared{facts:facts},nil
}
type prepared struct{facts output.Preparation}
func (*prepared) Close()error{return nil}
func (p *prepared) Send(ctx context.Context,_ []byte)(output.Outcome,error){
 facts:=p.facts
 if err:=ctx.Err();err!=nil{return output.Outcome{},err}
 if err:=record(&facts);err!=nil{return output.Outcome{},err}
 return output.Unknown(protocol.EntryMayHaveEntered)
}
func main(){base,err:=execution.NewImplementation(descriptor);if err!=nil{os.Exit(2)};code:=output.Main(implementation{base});if code==0&&len(os.Args)==2&&os.Args[1]=="output-wire-v6"{if record(nil)!=nil{code=97}};os.Exit(code)}
`, strconv.Quote(markerPath), strconv.Quote(label))
	formatted, err := format.Source([]byte(source))
	if err != nil {
		t.Fatal("independent output main syntax differs", err)
	}
	root := nativeRepository(t)
	license, err := os.ReadFile(filepath.Join(nativeGeneratedSourcePath(root, "sdk/output"), "LICENSE"))
	if err != nil {
		t.Fatal(err)
	}
	module := "module example.test/output-author\n\ngo 1.27.0\n\nrequire (\n enkv.sh/sdk/artifact v0.1.0\n enkv.sh/sdk/output v0.1.0\n enkv.sh/sdk/protocols/output v0.1.0\n enkv.sh/plugins/outputs/aws-secrets-manager v0.1.0\n)\n"
	descriptor, _, err := artifact.ReadDescriptor(t.Context(), filepath.Join(nativeGeneratedSourcePath(root, "plugins/aws-output"), "cmd/enkv-output-aws-secrets-manager/plugin.json"))
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
	workspace := nativePluginWorkspace(t, []string{nativeGeneratedSourcePath(root, "sdk/artifact"), directory, nativeGeneratedSourcePath(root, "sdk/output"), nativeGeneratedSourcePath(root, "protocols/output"), nativeGeneratedSourcePath(root, "plugins/aws-output")})
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	marker, err := artifactbuild.Run(ctx, artifactbuild.Config{Directory: directory, Descriptor: "plugin.json", Command: ".", Output: output, Workspace: workspace})
	if err != nil {
		t.Fatal("public independent output build failed", err)
	}
	metadata, err := artifact.VerifyBuild(ctx, output)
	if err != nil || metadata.MainModule != "example.test/output-author" || metadata.Command != metadata.MainModule || metadata.Role != "output" {
		t.Fatal("published independent output build differs", err)
	}
	identity, err := metadata.Identity()
	if err != nil || marker.Artifact != identity {
		t.Fatal("published independent output identity differs", err)
	}
	t.Logf("protocol-only output build=%s metadata=%s executable=%s module=%s command=%s", label, identity, metadata.Executable.SHA256, metadata.MainModule, metadata.Command)
	return metadata
}

func nativeOutputPluginSource(t *testing.T, s *workflowServer, cli string, plugins nativePluginFixture, scope, name string) (string, []workflowChild) {
	t.Helper()
	var source map[string]any
	if json.Unmarshal(workflowSetup(t, s, false), &source) != nil {
		t.Fatal("independent output setup unavailable")
	}
	source["domain"].(map[string]any)["name"] = name
	path := filepath.Join(scope, name+".json")
	nativeGeneratedWriteJSON(t, path, source)
	run := func(phase string, args ...string) workflowChild {
		return workflowRunEnvironment(t, s, cli, phase, observer.Policy{}, nil, plugins.Environment(t, path), append(args, "--source", path, "--source-format", "json", "--json")...)
	}
	initialized := run("init", "init")
	workflowResult(t, initialized, "success")
	nativePublicationSource(t, path, func(source map[string]any) {
		source["entries"] = map[string]any{"VALUE": map[string]any{"confidentiality": "plain", "recipients": []any{}, "source": map[string]any{"kind": "supplied", "value": "protocol-only input"}}}
		source["outputs"] = map[string]any{"destinations": map[string]any{"aws": map[string]any{"plugin": "aws-secrets-manager", "settings": map[string]any{"account": "123456789012", "region": "us-east-1"}}}, "routing": map[string]any{"default": []string{"aws"}}}
	})
	applied := run("apply", "apply")
	workflowResult(t, applied, "success")
	return path, []workflowChild{initialized, applied}
}

func nativeOutputPluginInvocations(t *testing.T, path string) ([]nativeOutputPluginInvocation, []byte) {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal("independent output callback did not run", err)
	}
	info, statErr := file.Stat()
	body, readErr := io.ReadAll(io.LimitReader(file, 65537))
	closeErr := file.Close()
	if statErr != nil || readErr != nil || closeErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || len(body) > 65536 {
		t.Fatal("independent output marker is not a bounded private image", statErr, readErr, closeErr)
	}
	var rows []nativeOutputPluginInvocation
	if err := json.Unmarshal(body, &rows); err != nil {
		t.Fatal("independent output marker differs", err)
	}
	return rows, body
}

func nativeOutputPluginCreateUnknown(t *testing.T, child workflowChild, coordinate string) nativePublicationOutput {
	t.Helper()
	var result nativePublicationOutput
	decoded := json.Unmarshal(child.out, &result) == nil
	envelope := decoded && result.Schema == "ProductResult/v1" && result.Operation == "publish" && result.State == "effect-unknown" && result.Summary == "output-unknown" && result.Replay == "none" && result.Effect == "not-applicable" && result.Payload.Schema == "OutputPayload/v3"
	coordinateMatches, actionCount := false, 0
	if len(result.Payload.Entries) == 1 {
		coordinateMatches = result.Payload.Entries[0].Coordinate == coordinate
		actionCount = len(result.Payload.Entries[0].Actions)
	}
	if child.code != 3 || !envelope || len(result.Payload.Entries) != 1 || !coordinateMatches || actionCount != 2 {
		t.Fatalf("fresh output unknown vector differs: exit=%d decoded=%t envelope=%t entries=%d coordinate_match=%t actions=%d", child.code, decoded, envelope, len(result.Payload.Entries), coordinateMatches, actionCount)
	}
	first, next := result.Payload.Entries[0].Actions[0], result.Payload.Entries[0].Actions[1]
	if first.Action == nil || *first.Action != "create-empty" || first.Attempt == nil || len(*first.Attempt) != 64 || first.Projection == nil || len(*first.Projection) != 64 || first.Disposition != "unknown" || first.Reason != 0 || !first.Remote || len(first.Blockers) != 0 || first.Evidence == nil || first.Evidence.Entry != "may-have-entered" || first.Evidence.Class != "unproved" || first.Evidence.Status != 0 || first.Evidence.Resource != "" {
		t.Fatalf("fresh create result differs: action=%t attempt=%t projection=%t unknown=%t reason=%d remote=%t blockers=%d evidence=%t", first.Action != nil && *first.Action == "create-empty", first.Attempt != nil, first.Projection != nil, first.Disposition == "unknown", first.Reason, first.Remote, len(first.Blockers), first.Evidence != nil)
	}
	if next.Action == nil || *next.Action != "write-value" || next.Projection == nil || len(*next.Projection) != 64 || next.Attempt != nil || next.Evidence != nil || next.Disposition != "not-sent" || next.Reason != uint16(core.AdmissionInvalid) || next.Remote || next.Late || len(next.Blockers) != 0 {
		t.Fatalf("later write result differs: action=%t attempt=%t projection=%t evidence=%t not_sent=%t reason=%d remote=%t late=%t blockers=%d", next.Action != nil && *next.Action == "write-value", next.Attempt != nil, next.Projection != nil, next.Evidence != nil, next.Disposition == "not-sent", next.Reason, next.Remote, next.Late, len(next.Blockers))
	}
	for _, text := range []string{*first.Attempt, *first.Projection, *next.Projection} {
		if nativePublicationID(t, text).IsZero() {
			t.Fatal("fresh publication lost a nonzero exact action identity")
		}
	}
	if *first.Projection == *next.Projection {
		t.Fatal("different fixed actions reused one projection")
	}
	return result
}

// full_only: false
func TestPublicNativeOutputUsesIndependentUpdatesWithoutReplayingUnknown(t *testing.T) {
	cli, _ := workflowExecutables(t)
	frozen, err := artifact.ExecutableIdentity(t.Context(), cli)
	if err != nil {
		t.Fatal(err)
	}
	private := nativeGeneratedPrivateDirectory(t)
	author, output := filepath.Join(private, "author"), filepath.Join(private, "build")
	if err := os.Mkdir(author, 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(private, "invocations.json")
	a := nativeOutputPluginBuild(t, author, output, marker, "A", "1.0.0")
	plugins := newNativePluginFixture(t, artifact.LocalPlugin{Name: "aws-secrets-manager", Directory: output})
	scope, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	aServer := newWorkflowServer(t, "aws", false)
	bServer := newWorkflowServer(t, "aws", false)
	for _, server := range []*workflowServer{aServer, bServer} {
		server.childLimit, server.childRequestLimit, server.objectLimit = 6, 2048, 256
		server.requestLimit = 6 * 2048
	}
	aSource, children := nativeOutputPluginSource(t, aServer, cli, plugins, scope, "independent-a")
	publish := func(server *workflowServer, source string) workflowChild {
		return workflowRunEnvironment(t, server, cli, "apply", observer.Policy{}, nil, plugins.Environment(t, source), "publish", "--source", source, "--source-format", "json", "--name", "VALUE", "--json")
	}
	const physical = "arn:aws:secretsmanager:us-east-1:123456789012:secret:VALUE"
	aPair := workflowReadNamedPair(t, aSource, "independent-a")
	aDomain := hex.EncodeToString(aPair.descriptor.DomainID[:])
	aCoordinate := nativePublicationCoordinate(t, aDomain, "ENKV/OUTPUT/AWS-SECRETS-MANAGER/v1", physical)
	aChild := publish(aServer, aSource)
	aResult := nativeOutputPluginCreateUnknown(t, aChild, aCoordinate)
	attemptA := *aResult.Payload.Entries[0].Actions[0].Attempt
	children = append(children, aChild)
	first, _ := nativeOutputPluginInvocations(t, marker)
	if len(first) != 1 || first[0].Build != "A" || !first[0].SDKReturned {
		t.Fatal("normal publication did not execute only independent A")
	}
	images := nativePublicationImages(t, aSource, filepath.Join(scope, aPair.reference))
	_, aHead := workflowHead(t, aServer)
	aObjects := aServer.objectCount()
	aRows := nativePublicationRows(nativePublicationSelectedParts(t, aServer))
	b := nativeOutputPluginBuild(t, author, output, marker, "B", "2.0.0")
	aIdentity, aErr := a.Identity()
	bIdentity, bErr := b.Identity()
	aFacts, aFactsErr := a.OutputFacts()
	bFacts, bFactsErr := b.OutputFacts()
	if aErr != nil || bErr != nil || aFactsErr != nil || bFactsErr != nil || aIdentity == bIdentity || a.Executable == b.Executable || aFacts.ExecutorID == bFacts.ExecutorID || aFacts.DependencyManifestID == bFacts.DependencyManifestID {
		t.Fatal("changed-source independent update reused exact A identities")
	}
	if aFacts.Descriptor.Wire != bFacts.Descriptor.Wire || !reflect.DeepEqual(aFacts.Descriptor.Output, bFacts.Descriptor.Output) {
		t.Fatal("compatible source update changed supported output meanings")
	}
	route, err := credentialroute.Decode(aFacts.Descriptor.Output.CredentialRoute)
	if err != nil {
		t.Fatal(err)
	}
	routeID, err := credentialroute.Identity(route)
	if err != nil {
		t.Fatal(err)
	}
	originalMarker, err := contract.InspectPublicationMarker(aRows[fmt.Sprintf("%d/%s", contract.PublicationMarkerSupportKind, attemptA)])
	if err != nil || originalMarker.ExecutorID != aFacts.ExecutorID.String() || originalMarker.CredentialRouteID != artifact.Digest(routeID).String() || originalMarker.State != contract.PublicationUnknown || originalMarker.Evidence.Class != contract.PublicationUnproved {
		t.Fatal("selected A marker did not retain its actual exact build", err)
	}
	bSource, bChildren := nativeOutputPluginSource(t, bServer, cli, plugins, scope, "independent-b")
	children = append(children, bChildren...)
	bPair := workflowReadNamedPair(t, bSource, "independent-b")
	bDomain := hex.EncodeToString(bPair.descriptor.DomainID[:])
	bCoordinate := nativePublicationCoordinate(t, bDomain, "ENKV/OUTPUT/AWS-SECRETS-MANAGER/v1", physical)
	if bDomain == aDomain || bCoordinate == aCoordinate || filepath.Dir(aSource) != filepath.Dir(bSource) {
		t.Fatal("fresh B coordinate did not share only the canonical application scope")
	}
	bChild := publish(bServer, bSource)
	bResult := nativeOutputPluginCreateUnknown(t, bChild, bCoordinate)
	children = append(children, bChild)
	rows, markerBefore := nativeOutputPluginInvocations(t, marker)
	if len(rows) != 2 {
		t.Fatal("normal publication did not execute exactly A and B")
	}
	for _, forbidden := range []string{"protocol-only input", workflowAccess("apply"), "offline-local-not-a-cloud-secret"} {
		if bytes.Contains(markerBefore, []byte(forbidden)) {
			t.Fatal("private credential or value bytes entered the safe invocation marker")
		}
	}
	for i, row := range rows {
		metadata, result, label := a, aResult, "A"
		if i == 1 {
			metadata, result, label = b, bResult, "B"
		}
		facts, err := metadata.OutputFacts()
		action := result.Payload.Entries[0].Actions[0]
		command := row.Preparation
		if err != nil || row.Build != label || row.PID <= 1 || !row.SDKReturned || command.Action != protocol.ActionCreateEmpty || command.Target.ServiceContractID != "ENKV/OUTPUT/AWS-SECRETS-MANAGER/v1" || command.Target.TargetContractID != "ENKV/OUTPUT/AWS-SECRETS-MANAGER/TARGET/v1" || command.Target.CanonicalTarget != physical || command.Target.ConsumerLocator != "" || !command.Target.LocatorRequiresCreation || command.Target.PayloadEncoding != protocol.EncodingRaw || command.Target.CreateValueBounds != (protocol.PayloadBounds{}) || command.Target.WriteValueBounds != (protocol.PayloadBounds{Minimum: 1, Maximum: 65536}) || command.PayloadLengthMode != protocol.LengthAbsent || command.PayloadLength != 0 || command.Target.Capabilities != (protocol.CapabilityCreateEmpty|protocol.CapabilityWriteValue|protocol.CapabilityDeleteOwned|protocol.CapabilityDeleteReservedSlot) || string(command.Target.TargetData) != `{"account":"123456789012","region":"us-east-1","name":"VALUE"}` || hex.EncodeToString(command.AttemptID[:]) != *action.Attempt || command.OwnedInstance != "" || command.ConditionalToken != "" {
			t.Fatal("actual independent SDK command lost its exact public bindings", i, err)
		}
		server := aServer
		if i == 1 {
			server = bServer
		}
		selected := nativePublicationRows(nativePublicationSelectedParts(t, server))
		marker, markerErr := contract.InspectPublicationMarker(selected[fmt.Sprintf("%d/%s", contract.PublicationMarkerSupportKind, *action.Attempt)])
		if markerErr != nil || marker.ExecutorID != facts.ExecutorID.String() || marker.CredentialRouteID != artifact.Digest(routeID).String() || hex.EncodeToString(marker.DomainID[:]) != result.Domain || hex.EncodeToString(marker.OperationID[:]) != result.OperationID || hex.EncodeToString(marker.AttemptID[:]) != *action.Attempt || hex.EncodeToString(marker.CoordinateID[:]) != result.Payload.Entries[0].Coordinate || hex.EncodeToString(marker.ProjectionCommitment[:]) != *action.Projection || hex.EncodeToString(marker.Evidence.ResponseContractDigest[:]) != action.Evidence.Response || !marker.Projection.PolicyDigest.IsZero() {
			t.Fatal("host result lost exact independent publication bindings", i, markerErr)
		}
		process, err := os.FindProcess(row.PID)
		if err != nil {
			t.Fatal(err)
		}
		signalErr := process.Signal(syscall.Signal(0))
		releaseErr := process.Release()
		if !errors.Is(signalErr, syscall.ESRCH) && !errors.Is(signalErr, os.ErrProcessDone) {
			t.Fatal("normal CLI returned with a surviving independent output child", errors.Join(signalErr, releaseErr))
		}
		if releaseErr != nil {
			t.Fatal("release independent output process observation", releaseErr)
		}
	}
	preview := workflowRunEnvironment(t, aServer, cli, "reader", observer.Policy{NoKMS: true}, nil, plugins.Environment(t, aSource), "plan", "--trusted", aSource, "--trusted-format", "json", "--publish", "--json")
	children = append(children, preview)
	workflowGETOnly(t, preview)
	var planned struct {
		State   string `json:"state_result"`
		Payload struct {
			Publication struct {
				Complete bool `json:"complete"`
				Entries  []struct {
					Coordinate *string  `json:"coordinate_id"`
					Target     string   `json:"physical_target"`
					Basis      string   `json:"basis"`
					Blockers   []string `json:"blocker_ids"`
					Remote     bool     `json:"remote_value_may_remain"`
				} `json:"entries"`
			} `json:"publication"`
		} `json:"payload"`
	}
	if preview.code != 0 || json.Unmarshal(preview.out, &planned) != nil || planned.State != "success" || !planned.Payload.Publication.Complete || len(planned.Payload.Publication.Entries) != 1 {
		t.Fatal("updated selection lost complete passive A preview")
	}
	entry := planned.Payload.Publication.Entries[0]
	if entry.Coordinate == nil || *entry.Coordinate != aCoordinate || entry.Target != physical || entry.Basis != "blocked" || !reflect.DeepEqual(entry.Blockers, []string{attemptA}) || !entry.Remote {
		t.Fatal("passive preview changed the exact original A blocker")
	}
	blocked := publish(aServer, aSource)
	children = append(children, blocked)
	retained := nativePublicationUnknown(t, blocked, aCoordinate, []string{"create-empty"})
	original, current := aResult.Payload.Entries[0].Actions[0], retained.Payload.Entries[0].Actions[0]
	if *current.Attempt != *original.Attempt || *current.Projection != *original.Projection || !reflect.DeepEqual(current.Evidence, original.Evidence) || !reflect.DeepEqual(current.Blockers, []string{attemptA}) || current.Remote != original.Remote || current.Late != original.Late {
		t.Fatal("blocked publication changed original A evidence")
	}
	_, markerAfter := nativeOutputPluginInvocations(t, marker)
	if !bytes.Equal(markerBefore, markerAfter) {
		t.Fatal("passive or blocked A revisit executed an output build")
	}
	_, afterHead := workflowHead(t, aServer)
	if !reflect.DeepEqual(aHead, afterHead) || aObjects != aServer.objectCount() || !reflect.DeepEqual(aRows, nativePublicationRows(nativePublicationSelectedParts(t, aServer))) {
		t.Fatal("blocked revisit changed exact retained A state")
	}
	nativePublicationUnchanged(t, images)
	after, err := artifact.ExecutableIdentity(t.Context(), cli)
	if err != nil || frozen != after {
		t.Fatal("independent plugin update changed frozen CLI", err)
	}
	nativeMaterializationJoined(t, children, 8)
	t.Logf("protocol-only unknown evidence: frozen_cli=%s A=%s B=%s A_blocker=%s", frozen.SHA256, aIdentity, bIdentity, attemptA)
}

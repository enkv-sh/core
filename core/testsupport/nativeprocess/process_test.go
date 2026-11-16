package nativeprocess

import (
	"context"
	"debug/buildinfo"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
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

func nativeRepository(t *testing.T) string {
	t.Helper()
	path, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(path, "compositions", "full", "go.mod")); err == nil {
			return path
		}
		parent := filepath.Dir(path)
		if parent == path {
			t.Fatal("implementation root unavailable")
		}
		path = parent
	}
}

// full_only: false
func TestNativeCaptureBodyReadCloseJoinsBeforeClear(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{"go.mod": "module nativebody\n\ngo 1.27.0\n", "runtime.go": runtimeSource, "runtime_test.go": nativeBodyReadCloseTest} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", nativeGoArguments("test", "-count=1", "-run", "^TestBodyReadCloseJoin$", ".")...)
	cmd.Dir = dir
	body, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("native materialized body failed ownership contract: %v\n%s", err, body)
	}
}

const nativeBodyReadCloseTest = `package nativeprocessruntime
import("bytes";"io";"testing";"time")
type blockedReader struct{body []byte; entered,release chan struct{}}
func(b *blockedReader)Read(p []byte)(int,error){close(b.entered);<-b.release;return copy(p,b.body),io.EOF}
func TestBodyReadCloseJoin(t *testing.T){
 source:=[]byte("independent-public-test-value");expected:=bytes.Clone(source);reader:=&blockedReader{body:source,entered:make(chan struct{}),release:make(chan struct{})};body:=&nativeProcessBody{Reader:reader,body:source};got:=make([]byte,len(source));readDone:=make(chan struct{});go func(){body.Read(got);close(readDone)}();<-reader.entered
 closeStarted,closeDone:=make(chan struct{}),make(chan struct{});go func(){close(closeStarted);body.Close();close(closeDone)}();<-closeStarted
 premature:=false;select{case <-closeDone:premature=true;case <-time.After(100*time.Millisecond):}
 close(reader.release);select{case <-readDone:case <-time.After(time.Second):t.Fatal("read did not join")};select{case <-closeDone:case <-time.After(time.Second):t.Fatal("close did not join")}
 if premature||!bytes.Equal(got,expected){t.Fatal("Close cleared borrowed bytes before the active Read joined")};if !bytes.Equal(source,make([]byte,len(source))){t.Fatal("Close retained materialized bytes")}
 if err:=body.Close();err!=nil{t.Fatal("Close is not idempotent")}
 checkResponseCloseJoin(t)
}
type blockedResponse struct{entered,release chan struct{};closes int}
func(b *blockedResponse)Read(p []byte)(int,error){close(b.entered);<-b.release;return 0,io.ErrClosedPipe}
func(b *blockedResponse)Close()error{b.closes++;close(b.release);return nil}
func checkResponseCloseJoin(t *testing.T){
 source:=&blockedResponse{entered:make(chan struct{}),release:make(chan struct{})};body:=&nativeProcessResponseBody{source:source,limit:1024};readDone,closeDone:=make(chan struct{}),make(chan struct{})
 go func(){body.Read(make([]byte,32));close(readDone)}();<-source.entered
 go func(){body.Close();close(closeDone)}()
 select{case <-readDone:case <-time.After(time.Second):t.Fatal("response Close did not release active Read")};select{case <-closeDone:case <-time.After(time.Second):t.Fatal("response Close did not join active Read")}
 if body.Close()!=nil||source.closes!=1{t.Fatal("response owner did not close exactly once")}
}
`

// full_only: false
func TestNativeCaptureChargesResponseBytesToProcessAllowance(t *testing.T) {
	for _, condition := range []string{"overflow", "under-limit", "shared"} {
		t.Run(condition, func(t *testing.T) {
			dir := t.TempDir()
			record := filepath.Join(dir, "capture")
			policy, err := json.Marshal(Policy{Version: 1, RecordPath: record, MaxRequests: 2, MaxBytes: 8})
			if err != nil {
				t.Fatal(err)
			}
			for name, body := range map[string][]byte{"go.mod": []byte("module nativeresponse\n\ngo 1.27.0\n"), "runtime.go": []byte(runtimeSource), "runtime_test.go": []byte(nativeResponseAllowanceTest), "policy.json": policy, "capture": nil} {
				if os.WriteFile(filepath.Join(dir, name), body, 0600) != nil {
					t.Fatal("response allowance fixture unavailable")
				}
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			command := exec.CommandContext(ctx, "go", nativeGoArguments("test", "-count=1", "-run", "^TestResponseAllowance$", ".")...)
			command.Dir = dir
			command.Env = append(os.Environ(), "ENKV_NATIVE_PROCESS_POLICY="+filepath.Join(dir, "policy.json"), "NATIVE_ALLOWANCE_CASE="+condition)
			if body, err := command.CombinedOutput(); err != nil {
				t.Fatalf("native process response allowance failed: %v\n%s", err, body)
			}
		})
	}
}

const nativeResponseAllowanceTest = `package nativeprocessruntime
import("io";"net/http";"os";"strings";"testing")
type responseRoundTripper struct{calls *int;closed *bool;bytes int}
type responseBody struct{io.Reader;closed *bool}
func(b responseBody)Close()error{*b.closed=true;return nil}
func(p responseRoundTripper)RoundTrip(r *http.Request)(*http.Response,error){*p.calls++;return &http.Response{StatusCode:200,Header:make(http.Header),Body:responseBody{strings.NewReader(strings.Repeat("x",p.bytes)),p.closed},ContentLength:-1,Request:r},nil}
func TestResponseAllowance(t *testing.T){
 condition:=os.Getenv("NATIVE_ALLOWANCE_CASE");size:=33;if condition=="under-limit"||condition=="shared"{size=2}
 request,err:=http.NewRequest("POST","https://service.invalid/owned",strings.NewReader("12345"));if err!=nil{t.Fatal(err)}
 calls,closed:=0,false;response,err:=nativeProcessRoundTrip(responseRoundTripper{&calls,&closed,size},request,"");if err!=nil{t.Fatal("underlying response was not returned",err)}
 body,err:=io.ReadAll(response.Body);closeErr:=response.Body.Close();defer clear(body)
 if calls!=1||!closed||closeErr!=nil{t.Fatal("actual response was not owned and closed")}
 if condition=="overflow"{if err==nil || len(body)>3 {t.Fatal("response consumed bytes beyond the remaining process allowance")};return}
 if err!=nil||len(body)!=2{t.Fatal("ordinary bounded response was refused",err)}
 if condition=="shared"{
  next,_:=http.NewRequest("GET","https://service.invalid/owned",nil);nextClosed:=false;response,err:=nativeProcessRoundTrip(responseRoundTripper{&calls,&nextClosed,33},next,"");if err!=nil{t.Fatal(err)}
  remaining,readErr:=io.ReadAll(response.Body);defer clear(remaining);response.Body.Close()
  if calls!=2||!nextClosed||readErr==nil||len(remaining)>1{t.Fatal("response bodies spent the same remaining process allowance")}
 }
}
`

// full_only: false
func TestNativeOverlayBuildsActualExecutable(t *testing.T) {
	root := nativeRepository(t)
	dir := t.TempDir()
	overlay, err := BuildOverlay(root, filepath.Join(dir, "overlay"))
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "enkv")
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	build := exec.CommandContext(ctx, "go", nativeGoArguments("build", "-mod=readonly", "-tags=netgo", "-trimpath", "-buildvcs=false", "-overlay="+overlay.Path, "-o", binary, "./cmd/enkv")...)
	build.Dir = filepath.Join(root, "compositions", "full")
	prepareNativeModule(t, root, build, binary+".mod")
	if body, err := build.CombinedOutput(); err != nil {
		t.Fatalf("actual public executable overlay did not build: %v\n%s", err, body)
	}
	nativeRequireRaceMode(t, binary)
	helper := filepath.Join(dir, "enkv-public-reconstruct")
	helperDirectory := filepath.Join(root, "tests", "live", "publicprocess")
	helperArgs := nativeGoArguments("build", "-mod=readonly", "-tags=netgo", "-trimpath", "-buildvcs=false", "-overlay="+overlay.Path, "-o", helper)
	helperSources, err := filepath.Glob(filepath.Join(helperDirectory, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range helperSources {
		if !strings.HasSuffix(path, "_test.go") {
			helperArgs = append(helperArgs, path)
		}
	}
	helperArgs = append(helperArgs, filepath.Join(helperDirectory, "nativeprocess_observer.go"))
	helperBuild := exec.CommandContext(ctx, "go", helperArgs...)
	helperBuild.Dir = filepath.Join(root, "compositions", "full")
	prepareNativeModule(t, root, helperBuild, helper+".mod")
	if body, err := helperBuild.CombinedOutput(); err != nil {
		t.Fatalf("actual reconstruction helper overlay did not build: %v\n%s", err, body)
	}
	nativeRequireRaceMode(t, helper)
	record := filepath.Join(dir, "capture.jsonl")
	if err := os.WriteFile(record, nil, 0600); err != nil {
		t.Fatal(err)
	}
	policy := Policy{Version: 1, RecordPath: record, MaxRequests: 1, MaxBytes: 1024}
	encoded, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(policyPath, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	environment, err := (StandardContext{Mode: "aws-sso", Home: dir, Profile: "unused"}).Environment("aws", os.Environ(), filepath.Join(dir, "absent-credentials"))
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"plan", "--trusted", filepath.Join(dir, "absent-source"), "--format", "json", "--json"},
		{"inspect", "--json"}, {"preview", "--json"}, {"end-work", "--json"}, {"recheck", "--json"}, {"restore-signer", "--json"},
	} {
		t.Run(args[0], func(t *testing.T) {
			if err := os.WriteFile(record, nil, 0600); err != nil {
				t.Fatal(err)
			}
			child := exec.CommandContext(ctx, binary, args...)
			child.Dir = dir
			child.Env = append(environment, "ENKV_NATIVE_PROCESS_POLICY="+policyPath)
			body, err := child.CombinedOutput()
			exit, ok := err.(*exec.ExitError)
			if !ok || exit.ExitCode() != 2 {
				t.Fatalf("missing-input child did not join refusal: %v\n%s", err, body)
			}
			capture, err := ReadCapture(record)
			if err != nil || len(capture.Events) != 1 || capture.Events[0].Kind != "footer" || capture.Events[0].Code != 2 {
				t.Fatal("input refusal made a native request or lost its joined footer", err)
			}
		})
	}

}

// full_only: false
func TestNativeCaptureGCSMultipartClassifiesExactKeyAndPreservesBody(t *testing.T) {
	dir := t.TempDir()
	record := filepath.Join(dir, "capture")
	policy, err := json.Marshal(Policy{Version: 1, RecordPath: record, Bucket: "fixture-bucket", Prefix: "fixture", MaxRequests: 4, MaxBytes: 16384})
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{"go.mod": []byte("module nativegcs\n\ngo 1.27.0\n"), "runtime.go": []byte(runtimeSource), "runtime_test.go": []byte(nativeGCSMultipartTest), "policy.json": policy, "capture": nil} {
		if os.WriteFile(filepath.Join(dir, name), body, 0600) != nil {
			t.Fatal("multipart runtime fixture unavailable")
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "go", nativeGoArguments("test", "-count=1", "-run", "^TestGCSMultipart$", ".")...)
	command.Dir = dir
	command.Env = append(os.Environ(), "ENKV_NATIVE_PROCESS_POLICY="+filepath.Join(dir, "policy.json"))
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("native GCS multipart observation failed: %v\n%s", err, output)
	}
	capture, err := ReadCapture(record)
	if err != nil {
		t.Fatal("multipart observation lost joined footer", err)
	}
	operations := []string{}
	for _, event := range capture.Events {
		if event.Kind == "http-start" && event.Sent {
			operations = append(operations, event.Operation)
		}
	}
	if len(operations) != 2 || operations[0] != "head-write" || operations[1] != "store-write" {
		t.Fatal("multipart metadata did not fix exact HEAD/object classification")
	}
}

const nativeGCSMultipartTest = `package nativeprocessruntime
import("bytes";"io";"mime/multipart";"net/http";"net/textproto";"strings";"testing")
type gcsInput struct{*bytes.Reader;closes int}
func(b *gcsInput)Close()error{b.closes++;return nil}
type gcsSend struct{want []byte;calls *int;borrowed *[]byte}
func(s gcsSend)RoundTrip(r *http.Request)(*http.Response,error){
 *s.calls++
 owner,ok:=r.Body.(*nativeProcessBody);if !ok{panic("dispatch lost exact body owner")};*s.borrowed=owner.body
 got,err:=io.ReadAll(r.Body);defer clear(got)
 if err!=nil||!bytes.Equal(got,s.want){panic("multipart dispatch bytes differ")}
 return &http.Response{StatusCode:200,ContentLength:0,Header:make(http.Header),Body:io.NopCloser(strings.NewReader("")),Request:r},nil
}
func TestGCSMultipart(t *testing.T){
 calls:=0
 for _,tc:=range []struct{metadata string;accepted bool}{{` + "`" + `{"name":"fixture/HEAD","contentType":"application/octet-stream"}` + "`" + `,true},{` + "`" + `{"name":"fixture/data","contentType":"application/octet-stream"}` + "`" + `,true},{` + "`" + `{"name":"fixture/HEAD","name":"fixture/other"}` + "`" + `,false},{` + "`" + `{"name":"outside/HEAD"}` + "`" + `,false}}{
  var raw bytes.Buffer;writer:=multipart.NewWriter(&raw)
  header:=make(textproto.MIMEHeader);header.Set("Content-Type","application/json");part,err:=writer.CreatePart(header);if err!=nil{t.Fatal(err)};io.WriteString(part,tc.metadata)
  header=make(textproto.MIMEHeader);header.Set("Content-Type","application/octet-stream");part,err=writer.CreatePart(header);if err!=nil{t.Fatal(err)};part.Write([]byte{0,255,1,2,3,4});writer.Close()
  expected:=bytes.Clone(raw.Bytes());input:=&gcsInput{Reader:bytes.NewReader(raw.Bytes())}
  request,err:=http.NewRequest("POST","https://storage.us-central1.rep.googleapis.com/upload/storage/v1/b/fixture-bucket/o?uploadType=multipart",input);if err!=nil{t.Fatal(err)}
  request.ContentLength=int64(raw.Len());request.Header.Set("Content-Type","multipart/related; boundary="+writer.Boundary());request.GetBody=func()(io.ReadCloser,error){panic("observer retained replay authority")}
  before:=calls;var borrowed []byte;response,err:=nativeProcessRoundTrip(gcsSend{expected,&calls,&borrowed},request,"")
  if response!=nil{io.Copy(io.Discard,response.Body);response.Body.Close()}
  if tc.accepted&&(err!=nil||calls!=before+1)||!tc.accepted&&(err==nil||calls!=before){t.Fatal("multipart exact key admission differs",err)}
  owner,ok:=request.Body.(*nativeProcessBody)
  if input.closes!=1||!ok||!owner.closed||owner.body!=nil||request.GetBody!=nil||request.ContentLength!=int64(len(expected)){t.Fatal("metadata projection lost exact close/clear/replay ownership")}
  if owner.Reader!=nil{t.Fatal("closed metadata owner retained its reader")}
  if tc.accepted&&(len(borrowed)!=len(expected)||!bytes.Equal(borrowed,make([]byte,len(borrowed))))||!tc.accepted&&borrowed!=nil{t.Fatal("metadata copy retained bytes after dispatch or reached refused dispatch")}
  clear(expected)
 }
 nativeProcessFinish(0)
}
`

// full_only: false
func TestNativeCaptureUnsentRequestCloseJoins(t *testing.T) {
	for _, condition := range []string{"policy-load", "prefix", "budget", "record", "head-contention", "close-error", "delegated"} {
		t.Run(condition, func(t *testing.T) {
			dir := t.TempDir()
			record := filepath.Join(dir, "capture")
			policy := Policy{Version: 1, RecordPath: record, Bucket: "fixture-bucket", Prefix: "fixture", MaxRequests: 4, MaxBytes: 1024}
			if condition == "budget" {
				policy.MaxBytes = 1
			}
			if condition == "record" {
				policy.RecordPath = filepath.Join(dir, "absent", "capture")
			}
			if condition == "head-contention" || condition == "close-error" {
				policy.Fault, policy.FaultOrdinal = "head-contention", 1
			}
			encoded, err := json.Marshal(policy)
			if err != nil {
				t.Fatal(err)
			}
			if condition == "policy-load" {
				encoded = []byte("{")
			}
			for name, body := range map[string][]byte{"go.mod": []byte("module nativeunsent\n\ngo 1.27.0\n"), "runtime.go": []byte(runtimeSource), "runtime_test.go": []byte(nativeUnsentCloseTest), "policy.json": encoded, "capture": nil} {
				if os.WriteFile(filepath.Join(dir, name), body, 0600) != nil {
					t.Fatal("unsent ownership fixture unavailable")
				}
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			command := exec.CommandContext(ctx, "go", nativeGoArguments("test", "-count=1", "-run", "^TestUnsentClose$", ".")...)
			command.Dir = dir
			command.Env = append(os.Environ(), "ENKV_NATIVE_PROCESS_POLICY="+filepath.Join(dir, "policy.json"), "ENKV_UNSENT_CONDITION="+condition)
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("native unsent ownership failed: %v\n%s", err, output)
			}
			capture, err := ReadProgress(record)
			if err != nil {
				t.Fatal("unsent control capture unavailable", err)
			}
			for _, event := range capture.Events {
				if event.TransportFailure != "" {
					t.Fatal("local refusal or successful delegation claimed a transport failure")
				}
			}
		})
	}
}

const nativeUnsentCloseTest = `package nativeprocessruntime
import("bytes";"errors";"io";"net/http";"os";"strings";"sync/atomic";"testing";"time")
var closeFailure=errors.New("owned close failed")
type unsentBody struct{*bytes.Reader;entered,release,joined chan struct{};closes atomic.Int32;fail bool}
func(b *unsentBody)Close()error{b.closes.Add(1);close(b.entered);<-b.release;close(b.joined);if b.fail{return closeFailure};return nil}
type unsentTransport struct{calls *atomic.Int32}
func(s unsentTransport)RoundTrip(r *http.Request)(*http.Response,error){s.calls.Add(1);return &http.Response{StatusCode:200,ContentLength:0,Header:make(http.Header),Body:io.NopCloser(strings.NewReader("")),Request:r},nil}
type unsentResult struct{response *http.Response;err error}
func TestUnsentClose(t *testing.T){
 condition:=os.Getenv("ENKV_UNSENT_CONDITION");path:="fixture/HEAD";if condition=="prefix"{path="outside/HEAD"}
 body:=&unsentBody{Reader:bytes.NewReader([]byte("exact request body")),entered:make(chan struct{}),release:make(chan struct{}),joined:make(chan struct{}),fail:condition=="close-error"}
 request,err:=http.NewRequest("PUT","https://s3.us-east-1.amazonaws.com/fixture-bucket/"+path,body);if err!=nil{t.Fatal(err)};request.ContentLength=18
 var calls atomic.Int32;returned:=make(chan unsentResult,1)
 go func(){response,err:=nativeProcessRoundTrip(unsentTransport{&calls},request,"");returned<-unsentResult{response,err}}()
 if condition=="delegated"{
  select{case result:=<-returned:if result.err!=nil||result.response==nil||calls.Load()!=1||body.closes.Load()!=0{t.Fatal("observer stole actual transport request ownership")};result.response.Body.Close();case <-time.After(time.Second):t.Fatal("actual transport did not retain its close responsibility")}
  close(body.release);if body.Close()!=nil{t.Fatal("delegate close failed")};return
 }
 select{case <-body.entered:case result:=<-returned:if result.response!=nil{result.response.Body.Close()};close(body.release);t.Fatal("unsent request returned without closing its owned body");case <-time.After(time.Second):close(body.release);t.Fatal("unsent request never retired its body")}
 select{case result:=<-returned:if result.response!=nil{result.response.Body.Close()};close(body.release);t.Fatal("unsent request did not join blocking Close");default:}
 close(body.release)
 var result unsentResult
 select{case result=<-returned:case <-time.After(time.Second):t.Fatal("unsent request close did not join return")}
 if calls.Load()!=0||body.closes.Load()!=1{t.Fatal("unsent request was sent or closed more than once")}
 select{case <-body.joined:default:t.Fatal("request returned before owned close joined")}
 if condition=="head-contention"{if result.err!=nil||result.response==nil||result.response.StatusCode!=412{t.Fatal("synthetic conditional rejection lost its response")}}else if condition=="close-error"{if !errors.Is(result.err,closeFailure)||result.response!=nil{t.Fatal("failed owned close was acknowledged or hidden")}}else if result.err==nil||result.response!=nil{t.Fatal("unsent refusal was acknowledged")}
 if result.response!=nil{result.response.Body.Close()}
}
`

// full_only: false
func TestNativeCaptureLostReplyRefusesOnlyLaterExactHEAD(t *testing.T) {
	dir := t.TempDir()
	record := filepath.Join(dir, "capture")
	policy, err := json.Marshal(Policy{Version: 1, RecordPath: record, Bucket: "fixture-bucket", Prefix: "fixture", MaxRequests: 8, MaxBytes: 1024, Fault: "lose-head-reply-and-observation", FaultOrdinal: 1})
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{"go.mod": []byte("module nativeunknown\n\ngo 1.27.0\n"), "runtime.go": []byte(runtimeSource), "runtime_test.go": []byte(nativeUnknownHeadTest), "policy.json": policy, "capture": nil} {
		if os.WriteFile(filepath.Join(dir, name), body, 0600) != nil {
			t.Fatal("unknown HEAD fixture unavailable")
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "go", nativeGoArguments("test", "-count=1", "-run", "^TestUnknownHead$", ".")...)
	command.Dir = dir
	command.Env = append(os.Environ(), "ENKV_NATIVE_PROCESS_POLICY="+filepath.Join(dir, "policy.json"))
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("native exact unknown control failed: %v\n%s", err, output)
	}
	capture, err := ReadCapture(record)
	if err != nil {
		t.Fatal("unknown control did not join capture", err)
	}
	starts := []Event{}
	for _, event := range capture.Events {
		if event.TransportFailure != "" {
			t.Fatal("controlled lost reply claimed a transport failure")
		}
		if event.Kind == "http-start" {
			starts = append(starts, event)
		}
	}
	if len(starts) != 4 || !starts[0].Sent || !starts[1].Sent || starts[2].Sent || !starts[3].Sent || starts[0].ObjectKeySHA256 != starts[2].ObjectKeySHA256 || starts[3].ObjectKeySHA256 == starts[2].ObjectKeySHA256 {
		t.Fatal("unknown control refused a precommit or unrelated observation")
	}
}

const nativeUnknownHeadTest = `package nativeprocessruntime
import("io";"net/http";"strings";"testing")
type unknownSend struct{calls *int}
func(s unknownSend)RoundTrip(r *http.Request)(*http.Response,error){*s.calls++;if r.Body!=nil{r.Body.Close()};return &http.Response{StatusCode:200,Header:make(http.Header),ContentLength:0,Body:io.NopCloser(strings.NewReader("")),Request:r},nil}
func TestUnknownHead(t *testing.T){
 calls:=0
 for i,step:=range []struct{method,key string;accepted bool}{{"GET","HEAD",true},{"PUT","HEAD",false},{"GET","HEAD",false},{"GET","object",true}}{
  request,_:=http.NewRequest(step.method,"https://s3.us-east-1.amazonaws.com/fixture-bucket/fixture/"+step.key,nil)
  response,err:=nativeProcessRoundTrip(unknownSend{&calls},request,"")
  if step.accepted {if err!=nil||response==nil{t.Fatal("ordinary observation was refused",i)}}else if err==nil||response!=nil{t.Fatal("controlled reply or observation was acknowledged",i)}
  if response!=nil{response.Body.Close()}
 }
 if calls!=3{t.Fatal("unknown control resent a conditional write or dispatched a refused observation")}
 nativeProcessFinish(0)
}
`

// full_only: false
func TestNativeCaptureAdmittedTrafficAndExactRecorderBound(t *testing.T) {
	for _, mode := range []string{"admitted-traffic", "exact-recorder-bound"} {
		t.Run(mode, func(t *testing.T) {
			directory := t.TempDir()
			record := filepath.Join(directory, "capture.jsonl")
			policy, err := json.Marshal(Policy{Version: 1, RecordPath: record, Bucket: "fixture-bucket", Prefix: "fixture", MaxRequests: 4096, MaxBytes: 64 << 20})
			if err != nil {
				t.Fatal(err)
			}
			for name, body := range map[string][]byte{
				"go.mod":          []byte("module nativecapturecapacity\n\ngo 1.27.0\n"),
				"runtime.go":      []byte(runtimeSource),
				"runtime_test.go": []byte(nativeCaptureCapacityTest),
				"policy.json":     policy,
				"capture.jsonl":   nil,
			} {
				if err := os.WriteFile(filepath.Join(directory, name), body, 0600); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			command := exec.CommandContext(ctx, "go", nativeGoArguments("test", "-count=1", "-run", "^TestCaptureCapacityProbe$", "-v", ".")...)
			command.Dir = directory
			command.Env = append(os.Environ(), "ENKV_NATIVE_PROCESS_POLICY="+filepath.Join(directory, "policy.json"), "NATIVE_CAPTURE_CAPACITY_MODE="+mode, "NATIVE_CAPTURE_TOTAL_BYTES="+strconv.Itoa(MaxCaptureBytes))
			output, err := command.CombinedOutput()
			if err != nil || !strings.Contains(string(output), "--- PASS: TestCaptureCapacityProbe (") {
				t.Fatalf("native capture capacity probe did not pass: %v\n%s", err, output)
			}
			if mode != "admitted-traffic" {
				return
			}
			info, err := os.Stat(record)
			if err != nil || info.Size() <= 1<<20 {
				t.Fatal("admitted traffic did not cross the former total capture bound", err)
			}
			capture, err := ReadCapture(record)
			if err != nil || len(capture.Events) != 4*4096+1 {
				t.Fatal("admitted traffic lost an observation or joined footer", err)
			}
			for i := 0; i < 4096; i++ {
				events := capture.Events[4*i : 4*i+4]
				if events[0].Kind != "source-kind" || events[1].Kind != "http-start" || events[2].Kind != "http-return" || events[3].Kind != "store-result" {
					t.Fatal("admitted request lost an event family", i)
				}
				for _, event := range events[1:] {
					if event.Sequence != uint64(i+1) || !event.Sent || event.Operation != "store-write" {
						t.Fatal("admitted request lost its exact mutation join", i)
					}
				}
				if events[2].Status != 200 || events[3].WriteStatus != 1 {
					t.Fatal("admitted request lost its observed and typed results", i)
				}
			}
			footer := capture.Events[len(capture.Events)-1]
			if footer.Kind != "footer" || footer.Code != 0 {
				t.Fatal("admitted traffic lost its normal-return footer")
			}
		})
	}
}

const nativeCaptureCapacityTest = `package nativeprocessruntime
import (
 "bytes"
 "context"
 "encoding/json"
 "fmt"
 "io"
 "net/http"
 "os"
 "strconv"
 "strings"
 "testing"
)
type captureCapacityTransport struct { calls int }
func (transport *captureCapacityTransport) RoundTrip(request *http.Request) (*http.Response, error) {
 transport.calls++
 if _, err := io.Copy(io.Discard, request.Body); err != nil { return nil, err }
 if err := request.Body.Close(); err != nil { return nil, err }
 return &http.Response{StatusCode:200, Header:make(http.Header), Body:io.NopCloser(strings.NewReader("")), Request:request}, nil
}
func TestCaptureCapacityProbe(t *testing.T) {
 p, err := nativeProcessLoad()
 if err != nil { t.Fatal(err) }
 switch os.Getenv("NATIVE_CAPTURE_CAPACITY_MODE") {
 case "admitted-traffic":
  transport := &captureCapacityTransport{}
  for i := 0; i < 4096; i++ {
   if err := nativeProcessRecord(nativeProcessEvent{Kind:"source-kind", SourceKind:"aws-sso", Count:1, Matched:true}); err != nil { t.Fatal("source observation refused", i, err) }
   key := fmt.Sprintf("fixture/object-%04d", i)
   ctx, scope := nativeProcessBeginStore(context.Background(), key, "store-write", "absent", nil)
   request, err := http.NewRequestWithContext(ctx, http.MethodPut, "https://s3.us-east-1.amazonaws.com/fixture-bucket/"+key, strings.NewReader("x"))
   if err != nil { t.Fatal(err) }
   request.Header.Set("If-None-Match", "*")
   response, err := nativeProcessRoundTrip(transport, request, "ordinary")
   if err != nil || response == nil || response.StatusCode != 200 { t.Fatal("admitted request lost its return", i, err) }
   if _, err := io.Copy(io.Discard, response.Body); err != nil { t.Fatal(err) }
   if err := response.Body.Close(); err != nil { t.Fatal(err) }
   // WriteAcknowledged=1 and ReasonNone=0 are fixed by contract.go.
   lost, err := nativeProcessStoreResult(scope, 1, 0, false)
   if err != nil || lost { t.Fatal("admitted Store result refused", i, err) }
  }
  if transport.calls != 4096 { t.Fatal("admitted transport count differs", transport.calls) }
  if err := nativeProcessRecord(nativeProcessEvent{Kind:"footer"}); err != nil { t.Fatal("admitted footer refused", err) }
 case "exact-recorder-bound":
  maximum, err := strconv.Atoi(os.Getenv("NATIVE_CAPTURE_TOTAL_BYTES"))
  if err != nil || maximum <= 0 { t.Fatal("expected capture bound unavailable", err) }
  event := nativeProcessEvent{Kind:"footer"}
  encoded, err := json.Marshal(event)
  if err != nil { t.Fatal(err) }
  encoded = append(encoded, '\n')
  for _, excess := range []int{0, 1} {
   file, err := os.OpenFile(p.RecordPath, os.O_WRONLY|os.O_TRUNC, 0600)
   if err != nil { t.Fatal(err) }
   before := int64(maximum-len(encoded)+excess)
   if err := file.Truncate(before); err != nil { file.Close(); t.Fatal(err) }
   if err := file.Close(); err != nil { t.Fatal(err) }
   err = nativeProcessRecord(event)
   info, statErr := os.Stat(p.RecordPath)
   if statErr != nil { t.Fatal(statErr) }
   if excess == 0 {
    if err != nil || info.Size() != int64(maximum) { t.Fatal("exact capture bound refused", err, info.Size()) }
    file, err := os.Open(p.RecordPath)
    if err != nil { t.Fatal(err) }
    tail := make([]byte, len(encoded))
    n, readErr := file.ReadAt(tail, before)
    closeErr := file.Close()
    if readErr != nil || closeErr != nil || n != len(encoded) || !bytes.Equal(tail, encoded) { t.Fatal("exact-fit event differs", readErr, closeErr) }
   } else if err == nil || info.Size() != before {
    t.Fatal("one-byte overflow was accepted or appended bytes", err, info.Size(), before)
   }
  }
 default:
  t.Fatal("unknown capture capacity probe")
 }
}
`

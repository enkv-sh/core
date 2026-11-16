package nativeprocess

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// full_only: false
func TestNativeStoreWriteLimitsBeforeDelegation(t *testing.T) {
	directory := t.TempDir()
	policy, err := json.Marshal(Policy{Version: 1, RecordPath: filepath.Join(directory, "capture"), Bucket: "fixture", Prefix: "owned", MaxRequests: 128, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{"go.mod": []byte("module nativewritelimits\n\ngo 1.27.0\n"), "runtime.go": []byte(runtimeSource), "runtime_test.go": []byte(nativeStoreWriteLimitsTest), "policy.json": policy, "capture": nil} {
		if err := os.WriteFile(filepath.Join(directory, name), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"aws-count", "aws-bytes", "gcp-count", "gcp-bytes", "legacy", "partial-count", "partial-bytes", "excess-count", "excess-bytes"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			command := exec.CommandContext(ctx, "go", nativeGoArguments("test", "-count=1", "-run", "^TestWriteLimit$", ".")...)
			command.Dir = directory
			command.Env = append(os.Environ(), "ENKV_NATIVE_PROCESS_POLICY="+filepath.Join(directory, "policy.json"), "WRITE_LIMIT_CASE="+name)
			if body, err := command.CombinedOutput(); err != nil {
				t.Fatalf("native write admission differs: %v\n%s", err, body)
			}
		})
	}
}

const nativeStoreWriteLimitsTest = `package nativeprocessruntime
import (
 "bytes"
 "encoding/json"
 "io"
 "mime/multipart"
 "net/http"
 "net/textproto"
 "os"
 "strings"
 "sync"
 "testing"
)
type ownedWriteBody struct { io.Reader; closes int }
func (b *ownedWriteBody) Close() error { b.closes++; return nil }
type writeTransport struct { calls int }
func (r *writeTransport) RoundTrip(request *http.Request) (*http.Response,error) {
 r.calls++
 if _,err:=io.Copy(io.Discard,request.Body); err!=nil { return nil,err }
 if err:=request.Body.Close(); err!=nil { return nil,err }
 return &http.Response{StatusCode:503,Header:make(http.Header),Body:io.NopCloser(strings.NewReader("")),Request:request},nil
}
func TestWriteLimit(t *testing.T) {
 name:=os.Getenv("WRITE_LIMIT_CASE")
 if _,err:=nativeProcessLoad(); err!=nil { t.Fatal(err) }
 counts,byteLimit:=uint64(2),uint64(1<<16)
 if strings.HasSuffix(name,"bytes") { counts,byteLimit=8,4 }
 if name=="legacy" { counts,byteLimit=0,0 }
 if name=="partial-count" { counts,byteLimit=1,0 }
 if name=="partial-bytes" { counts,byteLimit=0,1 }
 if name=="excess-count" { counts,byteLimit=129,1 }
 if name=="excess-bytes" { counts,byteLimit=1,(1<<20)+1 }
 fields:=map[string]any{"max_store_writes":counts,"max_store_write_bytes":byteLimit}
 encoded,err:=json.Marshal(fields); if err!=nil { t.Fatal(err) }
 // Load the valid baseline first so the regression reaches transport admission
 // even when an older runtime ignores these optional JSON fields.
 if err:=json.Unmarshal(encoded,&nativeProcessState.policy); err!=nil { t.Fatal(err) }
 invalid:=strings.HasPrefix(name,"partial-") || strings.HasPrefix(name,"excess-")
 if invalid {
  original,err:=os.ReadFile(os.Getenv("ENKV_NATIVE_PROCESS_POLICY")); if err!=nil { t.Fatal(err) }
  var policy map[string]any; if json.Unmarshal(original,&policy)!=nil { t.Fatal("baseline") }
  for key,value:=range fields { policy[key]=value }
  encoded,err:=json.Marshal(policy); if err!=nil { t.Fatal(err) }
  path:=t.TempDir()+"/policy.json"; if os.WriteFile(path,encoded,0600)!=nil { t.Fatal("policy") }
  nativeProcessState.once=sync.Once{}
  nativeProcessState.err=nil
  t.Setenv("ENKV_NATIVE_PROCESS_POLICY",path)
  if _,err:=nativeProcessLoad(); err==nil { t.Fatal("invalid write policy admitted") }
  return
 }
 transport:=&writeTransport{}
 run:=func(method,target string,bodyBytes []byte,contentType string,want bool) {
  t.Helper()
  request,err:=http.NewRequest(method,target,nil); if err!=nil { t.Fatal(err) }
  body:=&ownedWriteBody{Reader:bytes.NewReader(bodyBytes)}
  request.Body,request.ContentLength=body,int64(len(bodyBytes))
  request.Header.Set("Content-Type",contentType)
  if strings.Contains(target,"kms.") { request.Header.Set("X-Amz-Target","TrentService.Sign") }
  before:=transport.calls
  response,err:=nativeProcessRoundTrip(transport,request,"authority-private")
  if response!=nil { if _,e:=io.Copy(io.Discard,response.Body);e!=nil {t.Fatal(e)}; if e:=response.Body.Close();e!=nil {t.Fatal(e)} }
  if want && (err!=nil || response==nil || transport.calls!=before+1) { t.Fatal("permitted request refused",err) }
  if !want && (err==nil || response!=nil || transport.calls!=before) { t.Fatal("excess Store write reached transport") }
  if body.closes!=1 { t.Fatal("request body ownership differs",body.closes) }
  record,e:=os.ReadFile(nativeProcessState.policy.RecordPath); if e!=nil {t.Fatal(e)}
  lines:=bytes.Split(bytes.TrimSpace(record),[]byte("\n")); if len(lines)<2 {t.Fatal("capture missing")}
  for i,eventKind:=range []string{"http-start","http-return"} {
   var event nativeProcessEvent; if json.Unmarshal(lines[len(lines)-2+i],&event)!=nil || event.Kind!=eventKind || event.Sent!=want {t.Fatal("capture send differs")}
  }
 }
 const aws="https://s3.ap-southeast-2.amazonaws.com/fixture/owned/"
 // Reads and KMS remain available without consuming the Store write allowance.
 run("GET",aws+"HEAD",nil,"",true)
 run("POST","https://kms.ap-southeast-2.amazonaws.com/",[]byte("{}"),"",true)
 target,contentType,body:=aws+"object","",[]byte("ab")
 if strings.HasPrefix(name,"gcp-") {
  var buffer bytes.Buffer; writer:=multipart.NewWriter(&buffer)
  header:=textproto.MIMEHeader{"Content-Type":[]string{"application/json"}}
  part,e:=writer.CreatePart(header);if e!=nil {t.Fatal(e)};part.Write([]byte("{\"name\":\"owned/HEAD\"}"))
  part,e=writer.CreatePart(textproto.MIMEHeader{"Content-Type":[]string{"application/octet-stream"}});if e!=nil {t.Fatal(e)};part.Write([]byte("ab"))
  if writer.Close()!=nil {t.Fatal("multipart")}
  body=buffer.Bytes();contentType="multipart/related; boundary="+writer.Boundary()
  target="https://storage.australia-southeast1.rep.googleapis.com/upload/storage/v1/b/fixture/o?uploadType=multipart"
  if strings.HasSuffix(name,"bytes") {
   encoded,_:=json.Marshal(map[string]any{"max_store_write_bytes":2*len(body)})
   if json.Unmarshal(encoded,&nativeProcessState.policy)!=nil {t.Fatal("multipart limit")}
  }
 }
 method:="PUT"; if strings.HasPrefix(name,"gcp-") {method="POST"}
 run(method,target,body,contentType,true)
 run("GET",aws+"object",nil,"",true)
 // A retry is another physical attempt, including a provider failure reply.
 if strings.HasPrefix(name,"aws-") { target=aws+"HEAD" }
 run(method,target,body,contentType,true)
 run(method,target,body,contentType,name=="legacy")
 if name!="legacy" { run("GET",aws+"HEAD",nil,"",true) }
}
`

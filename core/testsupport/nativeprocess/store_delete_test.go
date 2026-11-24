package nativeprocess

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// full_only: false
func TestNativeCaptureConditionalDeleteRequiresJoinedOriginalCondition(t *testing.T) {
	key := strings.Repeat("a", 64)
	for _, provider := range []string{"aws", "gcp"} {
		for _, condition := range []string{"exact", "substituted-token", "missing-return", "absent-condition"} {
			t.Run(provider+"/"+condition, func(t *testing.T) {
				value, wire := []byte(`"original"`), "aws-if-match"
				if provider == "gcp" {
					value, wire = []byte("29"), "gcp-generation-match"
				}
				events := []Event{
					{Kind: "http-start", Operation: "store-delete", Sequence: 1, ObjectKeySHA256: key, Sent: true, LogicalConditionKind: "match", LogicalConditionValue: value, WireConditionKind: wire, WireConditionValue: value},
					{Kind: "http-return", Operation: "store-delete", Sequence: 1, ObjectKeySHA256: key, Sent: true, Status: 204},
					{Kind: "store-result", Operation: "store-delete", Sequence: 1, ObjectKeySHA256: key, Sent: true, WriteStatus: 1, LogicalConditionKind: "match", LogicalConditionValue: value, WireConditionKind: wire, WireConditionValue: value},
					{Kind: "footer"},
				}
				switch condition {
				case "substituted-token":
					events[0].WireConditionValue, events[2].WireConditionValue = []byte("30"), []byte("30")
				case "missing-return":
					events = append(events[:1:1], events[2:]...)
				case "absent-condition":
					events[0].LogicalConditionKind, events[2].LogicalConditionKind = "absent", "absent"
					events[0].LogicalConditionValue, events[2].LogicalConditionValue = nil, nil
				}
				var body bytes.Buffer
				for _, event := range events {
					if err := json.NewEncoder(&body).Encode(event); err != nil {
						t.Fatal(err)
					}
				}
				_, err := inspectCaptureImage(body.Bytes(), true)
				if (err == nil) != (condition == "exact") {
					t.Fatal("conditional-delete capture admission differs", err)
				}
			})
		}
	}
}

// full_only: false
func TestNativeCaptureStoreTransmissionFactsHaveExactOwner(t *testing.T) {
	for _, condition := range []string{"not-sent", "sent-and-not-sent", "unknown-reason", "reason-on-http", "not-sent-on-http", "not-sent-acknowledged"} {
		t.Run(condition, func(t *testing.T) {
			result := Event{Kind: "store-result", Operation: "store-delete", ObjectKeySHA256: strings.Repeat("a", 64), LogicalConditionKind: "match", LogicalConditionValue: []byte(`"old"`), WriteStatus: 4, StoreReason: 2, NotSent: true}
			valid := condition == "not-sent"
			switch condition {
			case "sent-and-not-sent":
				result.Sent = true
			case "unknown-reason":
				result.StoreReason = 8
			case "reason-on-http":
				result.Kind = "http-start"
			case "not-sent-on-http":
				result.Kind = "http-return"
				result.StoreReason = 0
				result.WriteStatus = 0
			case "not-sent-acknowledged":
				result.WriteStatus = 1
			}
			var body bytes.Buffer
			for _, event := range []Event{result, {Kind: "footer"}} {
				if err := json.NewEncoder(&body).Encode(event); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := inspectCaptureImage(body.Bytes(), true); (err == nil) != valid {
				t.Fatal("Store transmission fact owner differs", err)
			}
		})
	}
}

// full_only: false
func TestNativeStoreCaptureRetainsEnumerationAndDeleteResults(t *testing.T) {
	root := nativeRepository(t)
	for _, provider := range []string{"aws", "gcp"} {
		t.Run(provider, func(t *testing.T) {
			capture, raw := nativeStoreProbeCapture(t, root, provider, "TestNativeStoreEnumerationDeleteProbe", nativeStoreEnumerationDeleteProbe, "")
			defer clear(raw)
			listStarts, listReturns, deleteResults, unknownSent, unknownNotSent, refused := 0, 0, 0, 0, 0, 0
			for _, event := range capture.Events {
				if event.Operation == "store-list" {
					if event.Kind == "http-start" && event.Sent {
						listStarts++
					}
					if event.Kind == "http-return" && event.Sent && event.Status == 200 {
						listReturns++
					}
				}
				if event.Kind != "store-result" || event.Operation != "store-delete" {
					continue
				}
				deleteResults++
				if event.WriteStatus == 4 && event.StoreReason == 2 {
					if event.Sent && !event.NotSent {
						unknownSent++
					}
					if !event.Sent && event.NotSent && event.Sequence == 0 {
						unknownNotSent++
					}
				}
				if event.WriteStatus == 5 && event.StoreReason == 1 && !event.Sent {
					refused++
				}
			}
			if listStarts != 1 || listReturns != 1 || deleteResults != 5 || unknownSent != 1 || unknownNotSent != 1 || refused != 1 {
				t.Fatal("native exact enumeration/delete inventory differs", listStarts, listReturns, deleteResults, unknownSent, unknownNotSent, refused)
			}
			for _, sentinel := range []string{"fixture-access", "fixture-secret", "fixture-token", "reply-lost-private"} {
				if bytes.Contains(raw, []byte(sentinel)) {
					t.Fatal("private provider data entered capture")
				}
			}
		})
	}
}

const nativeStoreEnumerationDeleteProbe = `
// full_only: false
func TestNativeStoreEnumerationDeleteProbe(t *testing.T){
 ctx:=context.Background();var prefix,key string
 s:=nativeProbeStore(t,func(r *http.Request)(*http.Response,error){
  body:=fmt.Sprintf("{\"items\":[{\"name\":%q}]}",prefix+"foreign")
  if r.URL.Host=="s3.us-east-1.amazonaws.com"{body=fmt.Sprintf("<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>fixture-bucket</Name><Prefix>%s</Prefix><KeyCount>1</KeyCount><MaxKeys>256</MaxKeys><EncodingType>url</EncodingType><IsTruncated>false</IsTruncated><Contents><Key>%sforeign</Key></Contents></ListBucketResult>",prefix,prefix)}
  reply:=nativeProbeReply(r,200,false);reply.Body=io.NopCloser(bytes.NewBufferString(body));reply.ContentLength=int64(len(body));reply.Header.Set("Content-Length",fmt.Sprint(len(body)));return reply,nil
 },false)
 prefix=s.Descriptor().Prefix+"/"+fmt.Sprintf("%x",s.StoreConfiguration().DomainID)+"/";key=prefix+"result/"+fmt.Sprintf("%064x",8)
 if got:=s.ListPage(ctx,"");got.Status!=contract.ListPageOK||len(got.Keys)!=1||got.Keys[0]!=prefix+"foreign"{t.Fatal("actual enumeration differs",got.Status,got.Reason)}
 for _,mode:=range []string{"acknowledged","lost-reply","before-send","credentials"}{
  calls:=0
  s=nativeProbeStore(t,func(r *http.Request)(*http.Response,error){calls++;if mode=="lost-reply"{return nil,errors.New("reply-lost-private")};reply:=nativeProbeReply(r,200,false);reply.StatusCode=204;reply.Body=io.NopCloser(bytes.NewReader(nil));reply.ContentLength=0;reply.Header.Set("Content-Length","0");return reply,nil},mode=="credentials")
  if mode=="before-send"{nativeProbeBlockBeforeSend(s)}
  got:=s.DeleteIfToken(ctx,key,nativeProbeToken());want:=contract.WriteAcknowledged;if mode=="lost-reply"||mode=="before-send"{want=contract.WriteUnknown};if mode=="credentials"{want=contract.WriteRefused}
  wantCalls:=1;if mode=="before-send"||mode=="credentials"{wantCalls=0}
  if got.Status!=want||calls!=wantCalls||(mode=="before-send"||mode=="credentials")!=got.NotSent{t.Fatal("delete result/transmission differs",mode,got,calls)}
 }
 gate:=&nativeProbeClose{entered:make(chan struct{}),release:make(chan struct{})}
 s=nativeProbeStore(t,func(r *http.Request)(*http.Response,error){reply:=nativeProbeReply(r,200,false);reply.StatusCode=204;reply.Body=io.NopCloser(bytes.NewReader(nil));reply.ContentLength=0;reply.Header.Set("Content-Length","0");gate.ReadCloser=reply.Body;reply.Body=gate;return reply,nil},false)
 before:=nativeProbeTerminalCount(t);done:=make(chan contract.WriteResult,1)
 go func(){done<-s.DeleteIfToken(ctx,key,nativeProbeToken())}()
 select{case <-gate.entered:case <-time.After(5*time.Second):t.Fatal("delete response Close not reached")}
 premature:=nativeProbeTerminalCount(t)!=before;close(gate.release)
 select{case got:=<-done:if got.Status!=contract.WriteAcknowledged{t.Fatal("joined delete differs",got)};case <-time.After(5*time.Second):t.Fatal("delete did not join")}
 if premature||gate.calls.Load()!=1||nativeProbeTerminalCount(t)!=before+1{t.Fatal("delete typed result preceded response Close join")}
 nativeProcessFinish(0)
}
`

// full_only: false
func TestNativeListScopeRequiresExactBucketAndDomainPrefix(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{"go.mod": "module nativelistscope\n\ngo 1.27.0\n", "runtime.go": runtimeSource, "scope_test.go": nativeListScopeProbe} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "go", nativeGoArguments("test", "-count=1", "-run", "^TestExactListScope$", ".")...)
	command.Dir = dir
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("native exact list scope failed: %v\n%s", err, output)
	}
}

const nativeListScopeProbe = `package nativeprocessruntime
import("net/http";"net/url";"strings";"testing")
func TestExactListScope(t *testing.T){
 p:=nativeProcessPolicy{Bucket:"fixture-bucket",Prefix:"fixture",ListPrefix:"fixture/"+strings.Repeat("a",64)+"/"}
 for _,provider:=range []string{"aws","gcp"}{for _,mode:=range []string{"exact","wrong-bucket","wrong-prefix","duplicate-prefix","delimiter","larger-page","missing-independent-prefix","bad-query"}{t.Run(provider+"/"+mode,func(t *testing.T){
  q:=url.Values{"prefix":{p.ListPrefix}};target:="https://s3.us-east-1.amazonaws.com/fixture-bucket"
  if provider=="aws"{q.Set("list-type","2");q.Set("max-keys","256");q.Set("encoding-type","url")}else{target="https://storage.us-central1.rep.googleapis.com/storage/v1/b/fixture-bucket/o";q.Set("maxResults","256");q.Set("fields","items(name),nextPageToken");q.Set("alt","json");q.Set("prettyPrint","false")}
  policy:=p
  switch mode{case "wrong-bucket":target=strings.Replace(target,"fixture-bucket","other-bucket",1);case "wrong-prefix":q.Set("prefix","fixture/"+strings.Repeat("b",64)+"/");case "duplicate-prefix":q.Add("prefix",p.ListPrefix);case "delimiter":q.Set("delimiter","/");case "larger-page":if provider=="aws"{q.Set("max-keys","257")}else{q.Set("maxResults","257")};case "missing-independent-prefix":policy.ListPrefix=""}
  request,err:=http.NewRequest("GET",target+"?"+q.Encode(),nil);if err!=nil{t.Fatal(err)};if mode=="bad-query"{request.URL.RawQuery+="&unexpected=%ZZ"}
  if nativeProcessListScope(request,policy)!=(mode=="exact"){t.Fatal("listing scope widened",mode)}
 })}}
}
`

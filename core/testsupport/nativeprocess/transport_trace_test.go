package nativeprocess

import (
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
func TestNativeCaptureTransportTraceIsClosed(t *testing.T) {
	callbacks := []string{"dns_start", "dns_done", "connect_start", "connect_done", "tls_start", "tls_done", "wrote_headers", "wrote_request", "first_response_byte"}
	trace := func() map[string]any {
		value := map[string]any{"elapsed_ms": 600000}
		for _, name := range callbacks {
			value[name] = map[string]any{"observed": false, "elapsed_ms": 0}
		}
		return value
	}
	start := `{"kind":"http-start","operation":"store-read","sequence":1,"sent":true}` + "\n"
	returned := `{"kind":"http-return","operation":"store-read","sequence":1,"sent":true`
	footer := "\n" + `{"kind":"footer","code":2}` + "\n"
	image := func(value any) []byte {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return []byte(start + returned + `,"transport_trace":` + string(encoded) + `}` + footer)
	}
	for _, name := range append([]string{"unknown"}, callbacks...) {
		t.Run(name, func(t *testing.T) {
			value := trace()
			if name != "unknown" {
				value[name] = map[string]any{"observed": true, "elapsed_ms": 600000}
			}
			if _, err := InspectCapture(image(value)); err != nil {
				t.Fatal("closed callback observation refused", err)
			}
		})
	}
	for _, name := range callbacks {
		completion := name == "dns_done" || name == "connect_done" || name == "tls_done" || name == "wrote_request"
		for _, outcome := range []string{"no-error", "error"} {
			t.Run(name+"/"+outcome, func(t *testing.T) {
				value := trace()
				value[name] = map[string]any{"observed": true, "elapsed_ms": 600000, "outcome": outcome}
				_, err := InspectCapture(image(value))
				if (err == nil) != completion {
					t.Fatal("callback outcome accepted under the wrong contract", err)
				}
			})
		}
	}
	for name, damage := range map[string]func(map[string]any){
		"private-address":    func(v map[string]any) { v["address"] = "private address" },
		"private-error":      func(v map[string]any) { v["dns_done"].(map[string]any)["error"] = "private error" },
		"unknown-callback":   func(v map[string]any) { v["reused_connection"] = true },
		"missing-callback":   func(v map[string]any) { delete(v, "dns_start") },
		"missing-total":      func(v map[string]any) { delete(v, "elapsed_ms") },
		"null-callback":      func(v map[string]any) { v["dns_start"] = nil },
		"null-observed":      func(v map[string]any) { v["dns_start"].(map[string]any)["observed"] = nil },
		"null-time":          func(v map[string]any) { v["dns_start"].(map[string]any)["elapsed_ms"] = nil },
		"null-total":         func(v map[string]any) { v["elapsed_ms"] = nil },
		"missing-observed":   func(v map[string]any) { delete(v["dns_start"].(map[string]any), "observed") },
		"missing-time":       func(v map[string]any) { delete(v["dns_start"].(map[string]any), "elapsed_ms") },
		"negative-total":     func(v map[string]any) { v["elapsed_ms"] = -1 },
		"fractional-total":   func(v map[string]any) { v["elapsed_ms"] = 0.5 },
		"unbounded-total":    func(v map[string]any) { v["elapsed_ms"] = 600001 },
		"unknown-with-time":  func(v map[string]any) { v["dns_start"].(map[string]any)["elapsed_ms"] = 1 },
		"unobserved-outcome": func(v map[string]any) { v["tls_done"].(map[string]any)["outcome"] = "error" },
		"callback-after-return": func(v map[string]any) {
			v["elapsed_ms"] = 1
			v["dns_start"] = map[string]any{"observed": true, "elapsed_ms": 2}
		},
	} {
		t.Run(name, func(t *testing.T) {
			value := trace()
			damage(value)
			if _, err := InspectCapture(image(value)); err == nil {
				t.Fatal("invalid or private transport trace admitted")
			}
		})
	}
	for _, outcome := range []any{nil, "", "private failure", true, 1} {
		value := trace()
		value["tls_done"] = map[string]any{"observed": true, "elapsed_ms": 0, "outcome": outcome}
		if _, err := InspectCapture(image(value)); err == nil {
			t.Fatal("non-closed completion outcome admitted")
		}
	}
	if _, err := InspectCapture(image(nil)); err == nil {
		t.Fatal("null transport trace admitted")
	}
	value := trace()
	value["tls_done"] = map[string]any{"observed": true, "elapsed_ms": 0, "outcome": "error"}
	complete := string(image(value))
	for name, damaged := range map[string]string{
		"duplicate-outcome":         strings.Replace(complete, `"outcome":"error"`, `"outcome":"private text","outcome":"error"`, 1),
		"escaped-duplicate-outcome": strings.Replace(complete, `"outcome":"error"`, `"\u006futcome":"private text","outcome":"error"`, 1),
		"duplicate-callback":        strings.Replace(complete, `"tls_done":`, `"tls_done":null,"tls_done":`, 1),
		"duplicate-trace":           strings.Replace(complete, `"transport_trace":`, `"transport_trace":null,"transport_trace":`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := InspectCapture([]byte(damaged)); damaged == complete || err == nil {
				t.Fatal("duplicate member hid a non-closed transport observation")
			}
		})
	}
	encoded, err := json.Marshal(trace())
	if err != nil {
		t.Fatal(err)
	}
	field := `,"transport_trace":` + string(encoded)
	for _, name := range []string{"TRANSPORT_TRACE", "Transport_Trace"} {
		for owner, event := range map[string]string{
			"footer":      `{"kind":"footer","code":2}`,
			"sent-return": returned + `}`,
		} {
			for value, payload := range map[string]string{"null": "null", "empty": "{}", "closed": string(encoded)} {
				t.Run("noncanonical-field/"+name+"/"+owner+"/"+value, func(t *testing.T) {
					alternate := `,"` + name + `":` + payload
					image := strings.TrimSuffix(event, "}") + alternate + "}"
					if owner == "sent-return" {
						image = start + image + footer
					} else {
						image += "\n"
					}
					if _, err := InspectCapture([]byte(image)); err == nil {
						t.Fatal("noncanonical transport trace field admitted")
					}
				})
			}
		}
	}
	for name, damage := range map[string]func(map[string]any){
		"callback-name": func(v map[string]any) {
			v["DNS_START"] = v["dns_start"]
			delete(v, "dns_start")
		},
		"total-time": func(v map[string]any) {
			v["ELAPSED_MS"] = v["elapsed_ms"]
			delete(v, "elapsed_ms")
		},
		"callback-observed": func(v map[string]any) {
			callback := v["dns_start"].(map[string]any)
			callback["OBSERVED"] = callback["observed"]
			delete(callback, "observed")
		},
		"callback-time": func(v map[string]any) {
			callback := v["dns_start"].(map[string]any)
			callback["ELAPSED_MS"] = callback["elapsed_ms"]
			delete(callback, "elapsed_ms")
		},
		"callback-outcome": func(v map[string]any) {
			v["tls_done"] = map[string]any{"observed": true, "elapsed_ms": 0, "OUTCOME": "error"}
		},
	} {
		t.Run("noncanonical-nested/"+name, func(t *testing.T) {
			value := trace()
			damage(value)
			if _, err := InspectCapture(image(value)); err == nil {
				t.Fatal("noncanonical nested transport trace field admitted")
			}
		})
	}
	for _, baseline := range []string{
		start + returned + `}` + footer,
		`{"kind":"footer","code":2}` + "\n",
		`{"kind":"plaintext","count":1,"matched":true,"entry_sha256":"` + strings.Repeat("a", 64) + `"}` + footer,
		`{"kind":"store-result","operation":"store-write","object_key_sha256":"` + strings.Repeat("b", 64) + `","write_status":5,"not_sent":true,"logical_condition_kind":"absent"}` + footer,
	} {
		if _, err := InspectCapture([]byte(baseline)); err != nil {
			t.Fatal("event-owner control refused", err)
		}
		misplaced := strings.Replace(baseline, "}", field+"}", 1)
		if _, err := InspectCapture([]byte(misplaced)); err == nil {
			t.Fatal("trace admitted under another event owner")
		}
	}
	unsent := strings.ReplaceAll(string(image(trace())), `,"sent":true`, "")
	if _, err := InspectCapture([]byte(unsent)); err == nil {
		t.Fatal("undispatched request claimed network observations")
	}
}

// full_only: false
func TestNativeCaptureObservesTransportCallbacksWithoutChangingReturn(t *testing.T) {
	directory := t.TempDir()
	record := filepath.Join(directory, "capture")
	policy, err := json.Marshal(Policy{Version: 1, RecordPath: record, MaxRequests: 64, MaxBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{
		"go.mod": []byte("module nativetrace\n\ngo 1.27.0\n"), "runtime.go": []byte(runtimeSource),
		"runtime_test.go": []byte(nativeTransportTraceTest), "policy.json": policy, "capture": nil,
	} {
		if err := os.WriteFile(filepath.Join(directory, name), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "go", nativeGoArguments("test", "-count=1", "-run", "^TestTransportTrace$", ".")...)
	command.Dir = directory
	command.Env = append(os.Environ(), "ENKV_NATIVE_PROCESS_POLICY="+filepath.Join(directory, "policy.json"), "OTEL_SDK_DISABLED=true")
	if body, err := command.CombinedOutput(); err != nil {
		t.Fatalf("native transport callback observation differs: %v\n%s", err, body)
	}
	if _, err := ReadCapture(record); err != nil {
		t.Fatal("runtime trace did not satisfy the owning capture schema", err)
	}
}

const nativeTransportTraceTest = `package nativeprocessruntime

import (
 "bytes"
 "context"
 "crypto/tls"
 "encoding/json"
 "errors"
 "io"
 "net"
 "net/http"
 "net/http/httptrace"
 "os"
 "sync"
 "testing"
 "time"
)

type traceTransport struct {
 run func(*http.Request)
 response *http.Response
 err error
 calls int
 retained *httptrace.ClientTrace
}
func (s *traceTransport) RoundTrip(r *http.Request) (*http.Response,error) {
 s.calls++
 s.retained=httptrace.ContextClientTrace(r.Context())
 if s.run!=nil { s.run(r) }
 return s.response,s.err
}
type traceTimeout struct{}
func(traceTimeout)Error()string{panic("trace read a raw timeout message")}
func(traceTimeout)Timeout()bool{return true}
func(traceTimeout)Temporary()bool{return false}
type traceLateError struct{late func()}
func(*traceLateError)Error()string{panic("trace read a raw late error message")}
func(e *traceLateError)Is(error)bool{if e.late!=nil{late:=e.late;e.late=nil;late()};return false}
type traceCallback struct{Observed bool;ElapsedMS uint32;Outcome string}
type traceCallbackError struct{}
func(traceCallbackError)Error()string{panic("callback error message read")}
func(traceCallbackError)Is(error)bool{panic("callback error inspected")}
func(traceCallbackError)As(any)bool{panic("callback error classified")}
var traceNames=[]string{"dns_start","dns_done","connect_start","connect_done","tls_start","tls_done","wrote_headers","wrote_request","first_response_byte"}
func traceFire(trace *httptrace.ClientTrace,name string,err error) {
 switch name {
 case "dns_start": if trace.DNSStart!=nil{trace.DNSStart(httptrace.DNSStartInfo{Host:"private-host"})}
 case "dns_done": if trace.DNSDone!=nil{trace.DNSDone(httptrace.DNSDoneInfo{Addrs:[]net.IPAddr{{IP:net.IP{192,0,2,1}}},Err:err})}
 case "connect_start": if trace.ConnectStart!=nil{trace.ConnectStart("private-network","private-address")}
 case "connect_done": if trace.ConnectDone!=nil{trace.ConnectDone("private-network","private-address",err)}
 case "tls_start": if trace.TLSHandshakeStart!=nil{trace.TLSHandshakeStart()}
 case "tls_done": if trace.TLSHandshakeDone!=nil{trace.TLSHandshakeDone(tls.ConnectionState{ServerName:"private-server"},err)}
 case "wrote_headers": if trace.WroteHeaders!=nil{trace.WroteHeaders()}
 case "wrote_request": if trace.WroteRequest!=nil{trace.WroteRequest(httptrace.WroteRequestInfo{Err:err})}
 case "first_response_byte": if trace.GotFirstResponseByte!=nil{trace.GotFirstResponseByte()}
 }
}
func traceLast(t *testing.T)(map[string]json.RawMessage,[]byte) {
 t.Helper()
 image,err:=os.ReadFile(nativeProcessState.policy.RecordPath);if err!=nil{t.Fatal("trace capture unavailable")}
 for _,private:=range []string{"private-host","private-network","private-address","private-server"}{if bytes.Contains(image,[]byte(private)){t.Fatal("private callback input escaped capture")}}
 lines:=bytes.Split(bytes.TrimSpace(image),[]byte{'\n'});var fields map[string]json.RawMessage
 if len(lines)==0||json.Unmarshal(lines[len(lines)-1],&fields)!=nil{t.Fatal("trace return event unavailable")}
 return fields,image
}
func traceRead(t *testing.T,fields map[string]json.RawMessage,want map[string]bool)map[string]traceCallback {
 t.Helper()
 var trace map[string]json.RawMessage
 if json.Unmarshal(fields["transport_trace"],&trace)!=nil||len(trace)!=len(traceNames)+1{t.Fatal("delegated RoundTrip omitted its closed transport trace")}
 var total uint32;if json.Unmarshal(trace["elapsed_ms"],&total)!=nil||total>600000{t.Fatal("trace elapsed observation exceeded its bound")}
 result:=make(map[string]traceCallback)
 for _,name:=range traceNames {
  var callback struct{Observed bool ` + "`json:\"observed\"`" + `;ElapsedMS uint32 ` + "`json:\"elapsed_ms\"`" + `;Outcome string ` + "`json:\"outcome\"`" + `}
  if json.Unmarshal(trace[name],&callback)!=nil||callback.Observed!=want[name]||callback.ElapsedMS>total||!callback.Observed&&callback.ElapsedMS!=0{t.Fatalf("callback %s differs from its observed fact",name)}
  result[name]=traceCallback{callback.Observed,callback.ElapsedMS,callback.Outcome}
 }
 return result
}
func traceRequest(t *testing.T)*http.Request{t.Helper();r,err:=http.NewRequest("GET","https://service.invalid/owned",nil);if err!=nil{t.Fatal(err)};return r}
func TestTransportTrace(t *testing.T) {
 for _,name:=range append([]string{"unknown"},traceNames...) {t.Run(name,func(t *testing.T){
  original:=traceTimeout{};next:=&traceTransport{err:original}
  next.run=func(r *http.Request){trace:=httptrace.ContextClientTrace(r.Context());if trace==nil{t.Fatal("delegated RoundTrip has no transport trace")};if name!="unknown"{traceFire(trace,name,traceCallbackError{})}}
  response,err:=nativeProcessRoundTrip(next,traceRequest(t),"")
  if response!=nil||err!=original||next.calls!=1{t.Fatal("trace changed the original return or delegated call count")}
  fields,_:=traceLast(t);traceRead(t,fields,map[string]bool{name:name!="unknown"})
 })}
 for _,name:=range []string{"dns_done","connect_done","tls_done","wrote_request"}{for _,failed:=range []bool{false,true}{t.Run(name+"/completion-outcome",func(t *testing.T){
  var callbackErr error;want:="no-error";if failed{callbackErr=traceCallbackError{};want="error"}
  original:=traceTimeout{};next:=&traceTransport{err:original}
  next.run=func(r *http.Request){trace:=httptrace.ContextClientTrace(r.Context());traceFire(trace,name,callbackErr);time.Sleep(3*time.Millisecond);var opposite error=traceCallbackError{};if failed{opposite=nil};var group sync.WaitGroup;for i:=0;i<8;i++{group.Add(1);go func(){defer group.Done();traceFire(trace,name,opposite)}()};group.Wait()}
  response,err:=nativeProcessRoundTrip(next,traceRequest(t),"");if response!=nil||err!=original||next.calls!=1{t.Fatal("completion outcome changed return or call count")}
  fields,before:=traceLast(t);observed:=traceRead(t,fields,map[string]bool{name:true});if observed[name].Outcome!=want{t.Fatal("first completion outcome was omitted or overwritten")}
  traceFire(next.retained,name,callbackErr);_,after:=traceLast(t);if !bytes.Equal(before,after){t.Fatal("late completion changed published outcome")}
 })}}
 t.Run("write-wait-first-byte",func(t *testing.T){
  next:=&traceTransport{err:traceTimeout{}}
  next.run=func(r *http.Request){trace:=httptrace.ContextClientTrace(r.Context());if trace==nil{t.Fatal("delegated RoundTrip has no transport trace")};traceFire(trace,"wrote_headers",traceCallbackError{});time.Sleep(3*time.Millisecond);traceFire(trace,"wrote_request",traceCallbackError{});time.Sleep(3*time.Millisecond);traceFire(trace,"first_response_byte",traceCallbackError{})}
  nativeProcessRoundTrip(next,traceRequest(t),"")
  fields,_:=traceLast(t);observed:=traceRead(t,fields,map[string]bool{"wrote_headers":true,"wrote_request":true,"first_response_byte":true})
  if observed["wrote_request"].ElapsedMS<=observed["wrote_headers"].ElapsedMS||observed["first_response_byte"].ElapsedMS<=observed["wrote_request"].ElapsedMS{t.Fatal("write and response-wait callback times were collapsed")}
 })
 for _,tc:=range []struct{name string;err error;class string}{{"cancelled",context.Canceled,"cancelled"},{"deadline",context.DeadlineExceeded,"deadline"},{"transport-timeout",traceTimeout{},"timeout"}}{t.Run(tc.name,func(t *testing.T){
  next:=&traceTransport{err:tc.err};response,err:=nativeProcessRoundTrip(next,traceRequest(t),"");if response!=nil||err!=tc.err||next.calls!=1{t.Fatal("trace changed cancellation or timeout return")}
  fields,_:=traceLast(t);traceRead(t,fields,nil);var class string;if json.Unmarshal(fields["transport_failure"],&class)!=nil||class!=tc.class{t.Fatal("trace confused context termination and transport timeout")}
 })}
 for _,withError:=range []bool{false,true}{t.Run("response",func(t *testing.T){
  original:=&http.Response{StatusCode:503,Header:make(http.Header),Body:io.NopCloser(bytes.NewReader(nil))};next:=&traceTransport{response:original};if withError{next.err=traceTimeout{}}
  response,err:=nativeProcessRoundTrip(next,traceRequest(t),"");if response!=original||err!=next.err||next.calls!=1{t.Fatal("trace changed response-bearing return")};response.Body.Close()
  fields,_:=traceLast(t);traceRead(t,fields,nil);if _,present:=fields["transport_failure"];present{t.Fatal("response trace changed failure ownership")}
 })}
 t.Run("concurrent-first-observation",func(t *testing.T){
  next:=&traceTransport{err:traceTimeout{}}
  next.run=func(r *http.Request){trace:=httptrace.ContextClientTrace(r.Context());if trace==nil{t.Fatal("delegated RoundTrip has no transport trace")};traceFire(trace,"dns_start",traceCallbackError{});time.Sleep(5*time.Millisecond);var group sync.WaitGroup;for i:=0;i<16;i++{group.Add(1);go func(){defer group.Done();for j:=0;j<64;j++{for _,name:=range traceNames{traceFire(trace,name,traceCallbackError{})}}}()};group.Wait()}
  nativeProcessRoundTrip(next,traceRequest(t),"");fields,before:=traceLast(t);want:=map[string]bool{};for _,name:=range traceNames{want[name]=true};observed:=traceRead(t,fields,want)
  if observed["dns_start"].ElapsedMS>=observed["dns_done"].ElapsedMS{t.Fatal("repeated callback replaced its first observation")}
  var group sync.WaitGroup;for i:=0;i<16;i++{group.Add(1);go func(){defer group.Done();for _,name:=range traceNames{traceFire(next.retained,name,traceCallbackError{})}}()};group.Wait()
  _,after:=traceLast(t);if !bytes.Equal(before,after){t.Fatal("late callbacks changed the published capture")}
 })
 t.Run("freeze-before-error-inspection",func(t *testing.T){
  original:=&traceLateError{};next:=&traceTransport{err:original};next.run=func(r *http.Request){trace:=httptrace.ContextClientTrace(r.Context());if trace==nil{t.Fatal("delegated RoundTrip has no transport trace")};original.late=func(){for _,name:=range traceNames{traceFire(trace,name,traceCallbackError{})}}}
  response,err:=nativeProcessRoundTrip(next,traceRequest(t),"");if response!=nil||err!=original||next.calls!=1{t.Fatal("trace changed late-callback return")};fields,_:=traceLast(t);traceRead(t,fields,nil)
 })
 t.Run("synthetic-and-refused",func(t *testing.T){
  saved:=nativeProcessState.policy
  defer func(){nativeProcessState.policy=saved}()
  for _,synthetic:=range []bool{false,true}{
   nativeProcessState.policy=saved;nativeProcessState.policy.Bucket="fixture-bucket";nativeProcessState.policy.Prefix="fixture"
   next:=&traceTransport{err:traceTimeout{}};request:=traceRequest(t)
   if synthetic{nativeProcessState.policy.Fault="head-contention";nativeProcessState.policy.FaultOrdinal=nativeProcessState.heads+1;request,_=http.NewRequest("PUT","https://fixture-bucket.s3.region.amazonaws.com/fixture/HEAD",nil)}
   response,_:=nativeProcessRoundTrip(next,request,"");if response!=nil{response.Body.Close()};if next.calls!=0{t.Fatal("local outcome dispatched a transport")};fields,_:=traceLast(t);if _,present:=fields["transport_trace"];present{t.Fatal("local outcome claimed network observations")}
  }
 })
 t.Run("required-return-record",func(t *testing.T){
  saved:=nativeProcessState.policy.RecordPath;defer func(){nativeProcessState.policy.RecordPath=saved}()
  nativeProcessState.policy.RecordPath=saved+"-required";if err:=os.WriteFile(nativeProcessState.policy.RecordPath,nil,0600);err!=nil{t.Fatal("required-record control unavailable")}
  original:=&http.Response{StatusCode:200,Header:make(http.Header),Body:io.NopCloser(bytes.NewReader(nil))};next:=&traceTransport{response:original,run:func(*http.Request){nativeProcessState.policy.RecordPath=saved+"-absent"}}
  response,err:=nativeProcessRoundTrip(next,traceRequest(t),"");if response!=nil||!errors.Is(err,nativeProcessRefused)||next.calls!=1{t.Fatal("trace disabled the required safe return record")}
 })
 nativeProcessFinish(0)
}
`

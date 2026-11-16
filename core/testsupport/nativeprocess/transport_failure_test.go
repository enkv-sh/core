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
func TestNativeCaptureTransportFailureClassIsClosed(t *testing.T) {
	start := `{"kind":"http-start","operation":"store-read","sequence":1,"sent":true}` + "\n"
	returned := `{"kind":"http-return","operation":"store-read","sequence":1,"sent":true`
	footer := "\n" + `{"kind":"footer","code":2}` + "\n"
	for _, class := range []string{"cancelled", "deadline", "dns", "timeout", "tls", "connection", "eof", "other"} {
		image := start + returned + `,"transport_failure":"` + class + `"}` + footer
		if _, err := InspectCapture([]byte(image)); err != nil {
			t.Fatal("closed transport failure class refused", class)
		}
	}
	if _, err := InspectCapture([]byte(start + returned + `}` + footer)); err != nil {
		t.Fatal("legacy response-less capture refused")
	}
	for _, damage := range []string{
		`"transport_failure":""`, `"transport_failure":null`, `"transport_failure":"raw private error"`,
		`"transport_failure":"deadline","status":200`, `"transport_failure":"dns","permission_denied":true`,
		`"transport_failure":"timeout","quota_matched":true`,
	} {
		if _, err := InspectCapture([]byte(start + returned + `,` + damage + `}` + footer)); err == nil {
			t.Fatal("invalid transport classification admitted")
		}
	}
	for _, image := range []string{
		strings.Replace(start, `"sent":true`, `"sent":true,"transport_failure":"timeout"`, 1) + returned + `}` + footer,
		`{"kind":"footer","transport_failure":"timeout"}` + "\n",
		`{"kind":"plaintext","count":1,"matched":true,"entry_sha256":"` + strings.Repeat("a", 64) + `","transport_failure":"timeout"}` + footer,
		`{"kind":"source-kind","count":1,"matched":true,"source_kind":"aws-sso","transport_failure":"timeout"}` + footer,
		`{"kind":"store-result","operation":"store-write","object_key_sha256":"` + strings.Repeat("b", 64) + `","write_status":5,"not_sent":true,"logical_condition_kind":"absent","transport_failure":"timeout"}` + footer,
	} {
		baseline := strings.Replace(image, `,"transport_failure":"timeout"`, "", 1)
		if _, err := InspectCapture([]byte(baseline)); err != nil {
			t.Fatal("independent event-owner control refused")
		}
		if _, err := InspectCapture([]byte(image)); err == nil {
			t.Fatal("transport classification admitted under another event owner")
		}
	}
	unsent := strings.ReplaceAll(start+returned+`,"transport_failure":"timeout"}`+footer, `,"sent":true`, "")
	if _, err := InspectCapture([]byte(unsent)); err == nil {
		t.Fatal("undispatched request claimed a transport failure")
	}
}

// full_only: false
func TestNativeCaptureClassifiesTransportFailureWithoutChangingReturn(t *testing.T) {
	directory := t.TempDir()
	policy, err := json.Marshal(Policy{Version: 1, RecordPath: filepath.Join(directory, "capture"), MaxRequests: 64, MaxBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{
		"go.mod": []byte("module nativetransport\n\ngo 1.27.0\n"), "runtime.go": []byte(runtimeSource),
		"runtime_test.go": []byte(nativeTransportFailureTest), "policy.json": policy, "capture": nil,
	} {
		if err := os.WriteFile(filepath.Join(directory, name), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "go", nativeGoArguments("test", "-count=1", "-run", "^TestTransportFailure$", ".")...)
	command.Dir = directory
	command.Env = append(os.Environ(), "ENKV_NATIVE_PROCESS_POLICY="+filepath.Join(directory, "policy.json"))
	if body, err := command.CombinedOutput(); err != nil {
		t.Fatalf("native transport observation differs: %v\n%s", err, body)
	}
}

const nativeTransportFailureTest = `package nativeprocessruntime
import("bytes";"context";"crypto/tls";"crypto/x509";"encoding/json";"errors";"fmt";"io";"net";"net/http";"net/url";"os";"syscall";"testing")
type transportFailure struct{response *http.Response;err error;calls int}
func(n *transportFailure)RoundTrip(*http.Request)(*http.Response,error){n.calls++;return n.response,n.err}
type transportTimeout struct{}
func(transportTimeout)Error()string{return "private timeout address"}
func(transportTimeout)Timeout()bool{return true}
func(transportTimeout)Temporary()bool{return false}
type transportOpaqueError struct{}
func(transportOpaqueError)Error()string{panic("transport classification read an error message")}
func TestTransportFailure(t *testing.T){
 private:="private transport message and address"
 cases:=[]struct{name string;err error;class string}{
  {"cancelled",fmt.Errorf("%s: %w",private,context.Canceled),"cancelled"},
  {"deadline",&url.Error{Op:"Get",URL:private,Err:context.DeadlineExceeded},"deadline"},
  {"dns",&net.DNSError{Err:private,Name:private,IsTimeout:true},"dns"},
  {"timeout",&net.OpError{Op:"read",Net:"tcp",Err:transportTimeout{}},"timeout"},
  {"tls-certificate",&tls.CertificateVerificationError{Err:x509.UnknownAuthorityError{}},"tls"},
  {"tls-record",tls.RecordHeaderError{Msg:private},"tls"},
  {"tls-hostname",x509.HostnameError{Host:private},"tls"},
  {"tls-invalid",x509.CertificateInvalidError{Detail:private},"tls"},
  {"tls-roots",x509.SystemRootsError{Err:errors.New(private)},"tls"},
  {"tls-alert",tls.AlertError(42),"tls"},
  {"connection",&net.OpError{Op:"dial",Net:"tcp",Err:syscall.ECONNREFUSED},"connection"},
  {"connection-syscall",fmt.Errorf("%s: %w",private,syscall.ECONNRESET),"connection"},
  {"eof",&net.OpError{Op:"read",Net:"tcp",Err:io.EOF},"eof"},
  {"truncated",io.ErrUnexpectedEOF,"eof"},
  {"other",errors.New(private),"other"},
  {"opaque",transportOpaqueError{},"other"},
 }
 for _,tc:=range cases{t.Run(tc.name,func(t *testing.T){
  next:=&transportFailure{err:tc.err};request,_:=http.NewRequest("GET","https://service.invalid/owned",nil)
  response,err:=nativeProcessRoundTrip(next,request,"")
  if response!=nil||err!=tc.err||next.calls!=1{t.Fatal("observer changed delegated return or call count")}
  image,readErr:=os.ReadFile(nativeProcessState.policy.RecordPath);if readErr!=nil{t.Fatal("capture unavailable")}
  if bytes.Contains(image,[]byte(private)){t.Fatal("private transport detail escaped capture")}
  lines:=bytes.Split(bytes.TrimSpace(image),[]byte{'\n'});var event struct{Kind,Failure string;Status int;Sent bool}
  var fields map[string]json.RawMessage
  if json.Unmarshal(lines[len(lines)-1],&fields)!=nil||json.Unmarshal(fields["kind"],&event.Kind)!=nil||json.Unmarshal(fields["transport_failure"],&event.Failure)!=nil||json.Unmarshal(fields["sent"],&event.Sent)!=nil||event.Kind!="http-return"||!event.Sent||event.Failure!=tc.class{t.Fatal("response-less transport cause was not classified exactly")}
 })}
 for _,withError:=range []bool{false,true}{
  original:=&http.Response{StatusCode:503,Header:make(http.Header),Body:io.NopCloser(bytes.NewReader(nil))};next:=&transportFailure{response:original};if withError{next.err=errors.New(private)}
  request,_:=http.NewRequest("GET","https://service.invalid/owned",nil);response,err:=nativeProcessRoundTrip(next,request,"")
  if response!=original||err!=next.err||next.calls!=1{t.Fatal("observer changed response-bearing return")};response.Body.Close()
  image,_:=os.ReadFile(nativeProcessState.policy.RecordPath);lines:=bytes.Split(bytes.TrimSpace(image),[]byte{'\n'});var fields map[string]json.RawMessage;json.Unmarshal(lines[len(lines)-1],&fields)
  if _,present:=fields["transport_failure"];present{t.Fatal("response-bearing call claimed response-less transport failure")}
 }
 next:=&transportFailure{};request,_:=http.NewRequest("GET","https://service.invalid/owned",nil)
 response,err:=nativeProcessRoundTrip(next,request,"")
 if response!=nil||err!=nativeProcessRefused||next.calls!=1{t.Fatal("malformed delegated response changed its original refusal")}
 image,_:=os.ReadFile(nativeProcessState.policy.RecordPath);lines:=bytes.Split(bytes.TrimSpace(image),[]byte{'\n'});var fields map[string]json.RawMessage;json.Unmarshal(lines[len(lines)-1],&fields)
 if _,present:=fields["transport_failure"];present{t.Fatal("malformed response was mislabeled as a transport error")}
}
`

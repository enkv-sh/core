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
func TestNativeStoreReadOnlyPolicyRefusesBeforeDelegation(t *testing.T) {
	directory := t.TempDir()
	policy, err := json.Marshal(Policy{Version: 1, RecordPath: filepath.Join(directory, "capture"), Bucket: "fixture", Prefix: "owned", StoreReadOnly: true, MaxRequests: 256, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{
		"go.mod": []byte("module nativereadonly\n\ngo 1.27.0\n"), "runtime.go": []byte(runtimeSource),
		"runtime_test.go": []byte(nativeStoreReadOnlyTest), "policy.json": policy, "capture": nil,
	} {
		if err := os.WriteFile(filepath.Join(directory, name), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "go", nativeGoArguments("test", "-count=1", "-run", "^TestStoreReadOnly$", ".")...)
	command.Dir = directory
	command.Env = append(os.Environ(), "ENKV_NATIVE_PROCESS_POLICY="+filepath.Join(directory, "policy.json"))
	if body, err := command.CombinedOutput(); err != nil {
		t.Fatalf("native Store read-only admission differs: %v\n%s", err, body)
	}
}

const nativeStoreReadOnlyTest = `package nativeprocessruntime

import (
 "bytes"
 "encoding/json"
 "io"
 "net/http"
 "os"
 "strings"
 "testing"
)

type readOnlyRequestBody struct { io.Reader; closes int }
func (b *readOnlyRequestBody) Close() error { b.closes++; return nil }
type readOnlyTransport struct { calls int }
func (r *readOnlyTransport) RoundTrip(request *http.Request) (*http.Response, error) {
 r.calls++
 if _, err := io.Copy(io.Discard, request.Body); err != nil { return nil, err }
 if err := request.Body.Close(); err != nil { return nil, err }
 return &http.Response{StatusCode:200, Header:make(http.Header), Body:io.NopCloser(strings.NewReader("reply")), ContentLength:5, Request:request}, nil
}

func TestStoreReadOnly(t *testing.T) {
 if _, err := nativeProcessLoad(); err != nil { t.Fatal(err) }
 const aws = "https://s3.ap-southeast-2.amazonaws.com/fixture/owned/"
 const gcp = "https://storage.australia-southeast1.rep.googleapis.com/download/storage/v1/b/fixture/o/owned/"
 cases := []struct {
  name, method, target, source, bucket, prefix string
  readOnly, allowed bool
 }{
  {"aws-head", "GET", aws+"HEAD", "aws-sso", "fixture", "owned", true, true},
  {"aws-object", "GET", aws+"object?x-id=GetObject", "aws-assume-role", "fixture", "owned", true, true},
  {"gcp-head", "GET", gcp+"HEAD?alt=media&prettyPrint=false", "gcp-user-adc", "fixture", "owned", true, true},
  {"gcp-object", "GET", gcp+"object", "gcp-impersonated-adc", "fixture", "owned", true, true},
  {"gcp-metadata-path", "GET", "https://storage.australia-southeast1.rep.googleapis.com/storage/v1/b/fixture/o/owned/object", "gcp-user-adc", "fixture", "owned", true, false},
  {"aws-put", "PUT", aws+"object", "aws-sso", "fixture", "owned", true, false},
  {"aws-delete", "DELETE", aws+"object", "aws-sso", "fixture", "owned", true, false},
  {"aws-post", "POST", aws+"HEAD", "aws-sso", "fixture", "owned", true, false},
  {"aws-head-method", "HEAD", aws+"object", "aws-sso", "fixture", "owned", true, false},
  {"gcp-put", "PUT", gcp+"object", "gcp-user-adc", "fixture", "owned", true, false},
  {"gcp-delete", "DELETE", gcp+"object", "gcp-user-adc", "fixture", "owned", true, false},
  {"gcp-post", "POST", gcp+"object", "gcp-user-adc", "fixture", "owned", true, false},
  {"gcp-head-method", "HEAD", gcp+"object", "gcp-user-adc", "fixture", "owned", true, false},
  {"aws-list", "GET", "https://s3.ap-southeast-2.amazonaws.com/fixture?list-type=2&prefix=owned/", "aws-sso", "fixture", "owned", true, false},
  {"gcp-list", "GET", "https://storage.australia-southeast1.rep.googleapis.com/storage/v1/b/fixture/o?prefix=owned/", "gcp-user-adc", "fixture", "owned", true, false},
  {"aws-kms", "GET", "https://kms.ap-southeast-2.amazonaws.com/fixture/owned/object", "aws-sso", "fixture", "owned", true, false},
  {"gcp-kms", "GET", "https://australia-southeast1-cloudkms.googleapis.com/storage/v1/b/fixture/o/owned/object", "gcp-user-adc", "fixture", "owned", true, false},
  {"foreign-host", "GET", "https://foreign.invalid/fixture/owned/object", "aws-sso", "fixture", "owned", true, false},
  {"insecure-scheme", "GET", "http://s3.ap-southeast-2.amazonaws.com/fixture/owned/object", "aws-sso", "fixture", "owned", true, false},
  {"aws-other-bucket", "GET", "https://s3.ap-southeast-2.amazonaws.com/other/owned/object", "aws-sso", "fixture", "owned", true, false},
  {"gcp-other-bucket", "GET", "https://storage.australia-southeast1.rep.googleapis.com/download/storage/v1/b/other/o/owned/object", "gcp-user-adc", "fixture", "owned", true, false},
  {"aws-other-prefix", "GET", "https://s3.ap-southeast-2.amazonaws.com/fixture/unowned/object", "aws-sso", "fixture", "owned", true, false},
  {"gcp-other-prefix", "GET", "https://storage.australia-southeast1.rep.googleapis.com/download/storage/v1/b/fixture/o/unowned/object", "gcp-user-adc", "fixture", "owned", true, false},
  {"aws-as-gcp", "GET", aws+"object", "gcp-user-adc", "fixture", "owned", true, false},
  {"gcp-as-aws", "GET", gcp+"object", "aws-sso", "fixture", "owned", true, false},
  {"missing-bucket", "GET", aws+"object", "aws-sso", "", "owned", true, false},
  {"missing-prefix", "GET", aws+"object", "aws-sso", "fixture", "", true, false},
  {"aws-alternate-query", "GET", aws+"object?versionId=another", "aws-sso", "fixture", "owned", true, false},
  {"gcp-alternate-query", "GET", gcp+"object?name=owned/another", "gcp-user-adc", "fixture", "owned", true, false},
  {"duplicate-query", "GET", aws+"object?x-id=GetObject&x-id=PutObject", "aws-sso", "fixture", "owned", true, false},
  {"gcp-alternate-generation", "GET", gcp+"object?generation=1", "gcp-user-adc", "fixture", "owned", true, false},
  {"disabled-aws-put", "PUT", aws+"object", "aws-sso", "fixture", "owned", false, true},
  {"disabled-gcp-delete", "DELETE", gcp+"object", "gcp-user-adc", "fixture", "owned", false, true},
 }
 for _, tc := range cases {
  t.Run(tc.name, func(t *testing.T) {
   encoded, err := json.Marshal(map[string]any{"bucket":tc.bucket, "prefix":tc.prefix, "expected_source_kind":tc.source, "store_read_only":tc.readOnly})
   if err != nil { t.Fatal(err) }
   nativeProcessState.mu.Lock()
   err = json.Unmarshal(encoded, &nativeProcessState.policy)
   beforeSequence := nativeProcessState.sequence
   nativeProcessState.mu.Unlock()
   if err != nil { t.Fatal(err) }
   request, err := http.NewRequest(tc.method, tc.target, nil)
   if err != nil { t.Fatal(err) }
   body := &readOnlyRequestBody{Reader:strings.NewReader("{}")}
   request.Body, request.ContentLength = body, 2
   transport := &readOnlyTransport{}
   response, callErr := nativeProcessRoundTrip(transport, request, "authority-private")
   if response != nil {
    if _, err := io.Copy(io.Discard, response.Body); err != nil { t.Fatal(err) }
    if err := response.Body.Close(); err != nil { t.Fatal(err) }
   }
   if tc.allowed {
    if callErr != nil || response == nil || transport.calls != 1 { t.Fatal("permitted read or disabled-policy control was changed", callErr) }
   } else if callErr == nil || response != nil || transport.calls != 0 { t.Fatal("forbidden service request reached the delegated transport") }
   if body.closes != 1 { t.Fatal("request body ownership changed", body.closes) }
   record, err := os.ReadFile(nativeProcessState.policy.RecordPath)
   if err != nil { t.Fatal(err) }
   decoder := json.NewDecoder(bytes.NewReader(record))
   var events []nativeProcessEvent
   for {
    var event nativeProcessEvent
    if err := decoder.Decode(&event); err == io.EOF { break } else if err != nil { t.Fatal(err) }
    if event.Sequence == beforeSequence+1 { events = append(events, event) }
   }
   if len(events) != 2 || events[0].Kind != "http-start" || events[1].Kind != "http-return" || events[0].Sent != tc.allowed || events[1].Sent != tc.allowed || (events[1].Status == 200) != tc.allowed { t.Fatal("admission capture does not describe the physical send", events) }
  })
 }
}
`

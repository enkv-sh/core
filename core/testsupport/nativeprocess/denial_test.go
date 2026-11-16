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
func TestNativeCapturePermissionDenialUsesExactProviderEnvelope(t *testing.T) {
	dir := t.TempDir()
	record := filepath.Join(dir, "capture")
	policy, err := json.Marshal(Policy{Version: 1, RecordPath: record, MaxRequests: 64, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{
		"go.mod":          []byte("module nativedenial\n\ngo 1.27.0\n"),
		"runtime.go":      []byte(runtimeSource),
		"runtime_test.go": []byte(nativeDenialCaptureTest),
		"policy.json":     policy,
		"capture":         nil,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "go", nativeGoArguments("test", "-count=1", "-run", "^TestPermissionDenialCapture$", ".")...)
	command.Dir = dir
	command.Env = append(os.Environ(), "ENKV_NATIVE_PROCESS_POLICY="+filepath.Join(dir, "policy.json"))
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("native denial capture differs: %v\n%s", err, output)
	}
	if _, err := ReadCapture(record); err != nil {
		t.Fatal("native denial capture lost its complete event and footer evidence", err)
	}
}

const nativeDenialCaptureTest = `package nativeprocessruntime

import (
 "bytes"
 "encoding/json"
 "io"
 "net/http"
 "os"
 "reflect"
 "strings"
 "testing"
)

type denialBody struct {
 reader *strings.Reader
 closes int
 readFailure bool
 closeFailure bool
}
func (b *denialBody) Read(p []byte) (int, error) {
 n, err := b.reader.Read(p)
 if b.readFailure { return n, io.ErrUnexpectedEOF }
 return n, err
}
func (b *denialBody) Close() error { b.closes++; if b.closeFailure { return io.ErrClosedPipe }; return nil }

type denialTransport struct {
 body *denialBody
 status int
 calls int
 errorType string
}
func (s *denialTransport) RoundTrip(r *http.Request) (*http.Response, error) {
 s.calls++
 body, err := io.ReadAll(r.Body)
 closeErr := r.Body.Close()
 if err != nil || closeErr != nil || string(body) != "{}" { panic("denial request body changed") }
 header := make(http.Header)
 if s.errorType != "" { header.Set("X-Amzn-ErrorType", s.errorType) }
 return &http.Response{StatusCode:s.status, Header:header, Body:s.body, ContentLength:-1, Request:r}, nil
}

func TestPermissionDenialCapture(t *testing.T) {
 const awsURL = "https://kms.ap-southeast-2.amazonaws.com/"
 const gcpURL = "https://australia-southeast1-cloudkms.googleapis.com/v1/projects/fixture/locations/australia-southeast1/keyRings/fixture/cryptoKeys/fixture/cryptoKeyVersions/1:asymmetricDecrypt"
 const awsDenied = "{\"__type\":\"AccessDeniedException\"}"
 const gcpDenied = "{\"error\":{\"code\":403,\"status\":\"PERMISSION_DENIED\"}}"
 cases := []struct {
  name, target, body string
  status int
  denied, refused, readFailure bool
  operation string
  errorType string
  closeFailure bool
 }{
  {"aws_400_denied", awsURL, awsDenied, 400, true, false, false, "kms-decrypt", "", false},
  {"aws_403_denied", awsURL, awsDenied, 403, true, false, false, "kms-decrypt", "", false},
  {"aws_namespaced_denied", awsURL, "{\"__type\":\"com.amazonaws.kms#AccessDeniedException\"}", 400, true, false, false, "kms-decrypt", "", false},
  {"aws_normalized_namespace_and_suffix", awsURL, "{\"__type\":\"smithy.example#AccessDeniedException:detail\"}", 403, true, false, false, "kms-decrypt", "AccessDeniedException", false},
  {"aws_code_denied", awsURL, "{\"Code\":\"AccessDeniedException\"}", 400, true, false, false, "kms-decrypt", "", false},
  {"gcp_403_denied", gcpURL, gcpDenied, 403, true, false, false, "kms-decrypt", "", false},
  {"aws_invalid_ciphertext", awsURL, "{\"__type\":\"InvalidCiphertextException\"}", 400, false, false, false, "kms-decrypt", "", false},
  {"aws_throttled", awsURL, "{\"__type\":\"ThrottlingException\"}", 400, false, false, false, "kms-decrypt", "", false},
  {"aws_expired", awsURL, "{\"__type\":\"ExpiredTokenException\"}", 403, false, false, false, "kms-decrypt", "", false},
  {"aws_unrecognized_client", awsURL, "{\"__type\":\"UnrecognizedClientException\"}", 403, false, false, false, "kms-decrypt", "", false},
  {"aws_unauthenticated", awsURL, awsDenied, 401, false, false, false, "kms-decrypt", "", false},
  {"gcp_wrong_http_status", gcpURL, gcpDenied, 400, false, false, false, "kms-decrypt", "", false},
  {"aws_gcp_envelope", awsURL, gcpDenied, 403, false, false, false, "kms-decrypt", "", false},
  {"gcp_aws_envelope", gcpURL, awsDenied, 403, false, false, false, "kms-decrypt", "", false},
  {"aws_multiple_namespaces", awsURL, "{\"__type\":\"foreign#service#AccessDeniedException\"}", 403, false, false, false, "kms-decrypt", "", false},
  {"aws_other_code", awsURL, "{\"Code\":\"AccessDenied\"}", 403, false, false, false, "kms-decrypt", "", false},
  {"aws_conflicting_header", awsURL, awsDenied, 403, false, false, false, "kms-decrypt", "ExpiredTokenException", false},
  {"aws_conflicting_body", awsURL, "{\"__type\":\"AccessDeniedException\",\"Code\":\"ExpiredTokenException\"}", 403, false, false, false, "kms-decrypt", "", false},
  {"aws_conflicting_duplicate_type", awsURL, "{\"__type\":\"ExpiredTokenException\",\"__type\":\"AccessDeniedException\"}", 403, false, false, false, "kms-decrypt", "", false},
  {"malformed_json", awsURL, awsDenied[:len(awsDenied)-1], 403, false, false, false, "kms-decrypt", "", false},
  {"trailing_json", awsURL, awsDenied+"{}", 403, false, false, false, "kms-decrypt", "", false},
  {"foreign_endpoint", "https://foreign.invalid/", awsDenied, 403, false, false, false, "kms-decrypt", "", false},
  {"non_kms_operation", awsURL, awsDenied, 403, false, false, false, "store-write", "", false},
  {"aws_maximum_envelope", awsURL, awsDenied+strings.Repeat(" ", 16384-len(awsDenied)), 400, true, false, false, "kms-decrypt", "", false},
  {"aws_oversized_envelope", awsURL, awsDenied+strings.Repeat(" ", 16385-len(awsDenied)), 400, false, true, false, "kms-decrypt", "", false},
  {"aws_body_read_failure", awsURL, awsDenied, 400, false, true, true, "kms-decrypt", "", false},
  {"aws_body_close_failure", awsURL, awsDenied, 400, false, true, false, "kms-decrypt", "", true},
 }
 for _, tc := range cases {
  t.Run(tc.name, func(t *testing.T) {
   request, err := http.NewRequest("POST", tc.target, strings.NewReader("{}"))
   if err != nil { t.Fatal(err) }
   if tc.target != gcpURL && tc.operation != "store-write" { request.Header.Set("X-Amz-Target", "TrentService.Decrypt") }
   source := &denialBody{reader:strings.NewReader(tc.body), readFailure:tc.readFailure, closeFailure:tc.closeFailure}
   transport := &denialTransport{body:source, status:tc.status, errorType:tc.errorType}
   nativeProcessState.mu.Lock()
   beforeBytes, beforeSequence := nativeProcessState.bytes, nativeProcessState.sequence
   nativeProcessState.mu.Unlock()
   response, err := nativeProcessRoundTrip(transport, request, "authority-private")
   if tc.refused {
    if err == nil || response != nil { t.Fatal("incomplete denial body was returned as a qualified envelope") }
   } else {
    if err != nil || response == nil || response.StatusCode != tc.status { t.Fatal("observed denial changed response", err) }
    body, readErr := io.ReadAll(response.Body)
    firstClose, secondClose := response.Body.Close(), response.Body.Close()
    if readErr != nil || firstClose != nil || secondClose != nil || !bytes.Equal(body, []byte(tc.body)) { t.Fatal("denial observation changed response bytes or ownership", readErr) }
    clear(body)
   }
   nativeProcessState.mu.Lock()
   charged, sequence := nativeProcessState.bytes-beforeBytes, nativeProcessState.sequence
   nativeProcessState.mu.Unlock()
   if transport.calls != 1 || source.closes != 1 || charged != uint64(2+len(tc.body)) || sequence != beforeSequence+1 { t.Fatalf("denial byte/close/send ownership differs: calls=%d closes=%d bytes=%d", transport.calls, source.closes, charged) }
   record, err := os.ReadFile(nativeProcessState.policy.RecordPath)
   if err != nil { t.Fatal(err) }
   decoder := json.NewDecoder(bytes.NewReader(record))
   var events []nativeProcessEvent
   for {
    var event nativeProcessEvent
    err := decoder.Decode(&event)
    if err == io.EOF { break }
    if err != nil { t.Fatal(err) }
    events = append(events, event)
   }
   if len(events) != int(sequence)*2 { t.Fatal("denial capture event pair missing") }
   start, returned := events[len(events)-2], events[len(events)-1]
   if returned.TransportTrace == nil || returned.TransportTrace.ElapsedMS > 600000 { t.Fatal("denial capture lost its bounded transport observation") }
   expectedTrace := &nativeProcessTransportTrace{ElapsedMS:returned.TransportTrace.ElapsedMS}
   if !reflect.DeepEqual(start, nativeProcessEvent{Kind:"http-start", Operation:tc.operation, Role:"authority-private", Sequence:sequence, Sent:true}) ||
    !reflect.DeepEqual(returned, nativeProcessEvent{Kind:"http-return", Operation:tc.operation, Role:"authority-private", Sequence:sequence, Sent:true, Status:tc.status, PermissionDenied:tc.denied, QuotaMatched:true, TransportTrace:expectedTrace}) { t.Fatalf("provider denial classification differs: start=%+v return=%+v", start, returned) }
  })
 }
 nativeProcessFinish(0)
}
`

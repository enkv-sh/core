package nativeprocess

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"enkv.sh/core/contract"
)

// Expected WriteStatus numbers are fixed from core/contract/contract.go:
// acknowledged=1, precondition=2, conflict=3, unknown=4, refused=5.
// full_only: false
func TestNativeCaptureStoreResultsBindExactMutation(t *testing.T) {
	key := strings.Repeat("a", 64)
	base := []Event{
		{Kind: "http-start", Operation: "head-write", Sequence: 1, ObjectKeySHA256: key, Sent: true, LogicalConditionKind: "match", LogicalConditionValue: []byte(`"old"`), WireConditionKind: "aws-if-match", WireConditionValue: []byte(`"old"`)},
		{Kind: "http-return", Operation: "head-write", Sequence: 1, ObjectKeySHA256: key, Sent: true, Status: 200},
		{Kind: "store-result", Operation: "head-write", Sequence: 1, ObjectKeySHA256: key, Sent: true, WriteStatus: uint8(4), LogicalConditionKind: "match", LogicalConditionValue: []byte(`"old"`), WireConditionKind: "aws-if-match", WireConditionValue: []byte(`"old"`)},
		{Kind: "footer"},
	}
	for _, condition := range []string{"unknown", "acknowledged", "precondition", "conflict", "refused", "missing", "unsent", "duplicate", "foreign-sequence", "foreign-key", "foreign-operation", "sent-mismatch", "before-return", "zero-status", "invalid-status", "status-on-http", "return-key", "return-operation", "unsent-marked-sent"} {
		t.Run(condition, func(t *testing.T) {
			events := append([]Event(nil), base...)
			valid := false
			switch condition {
			case "unknown", "acknowledged", "precondition", "conflict", "refused":
				valid = true
				statuses := map[string]uint8{"unknown": 4, "acknowledged": 1, "precondition": 2, "conflict": 3, "refused": 5}
				events[2].WriteStatus = uint8(statuses[condition])
			case "missing":
				valid = true // A raw HTTP observation cannot assert typed settlement.
				events = append(events[:2], events[3:]...)
			case "unsent", "unsent-marked-sent":
				valid = condition == "unsent"
				events = []Event{{Kind: "store-result", Operation: "store-write", ObjectKeySHA256: key, WriteStatus: uint8(5), Sent: !valid, LogicalConditionKind: "absent"}, {Kind: "footer"}}
			case "duplicate":
				events = append(append(events[:3:3], events[2]), events[3:]...)
			case "foreign-sequence":
				events[2].Sequence = 2
			case "foreign-key":
				events[2].ObjectKeySHA256 = strings.Repeat("b", 64)
			case "foreign-operation":
				events[2].Operation = "store-write"
			case "sent-mismatch":
				events[2].Sent = false
			case "before-return":
				events[1], events[2] = events[2], events[1]
			case "zero-status":
				events[2].WriteStatus = 0
			case "invalid-status":
				events[2].WriteStatus = 6
			case "status-on-http":
				events[1].WriteStatus = uint8(1)
			case "return-key":
				events[1].ObjectKeySHA256 = strings.Repeat("b", 64)
			case "return-operation":
				events[1].Operation = "store-write"
			}
			var encoded bytes.Buffer
			for _, event := range events {
				if err := json.NewEncoder(&encoded).Encode(event); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := inspectCaptureImage(encoded.Bytes(), true); (err == nil) != valid {
				t.Fatal("native Store terminal admission differs", err)
			}
		})
	}
}

// full_only: false
func TestNativeStoreCapturePreservesProviderWriteResult(t *testing.T) {
	root := nativeRepository(t)
	for _, provider := range []string{"aws", "gcp"} {
		t.Run(provider, func(t *testing.T) {
			capture, raw := nativeStoreProbeCapture(t, root, provider, "TestNativeStoreResultProbe", "", "")
			defer clear(raw)
			returns := map[uint64]Event{}
			terminals, sent, unsent := 0, 0, 0
			for _, event := range capture.Events {
				if event.Kind == "http-return" {
					returns[event.Sequence] = event
				}
				if event.Kind != "store-result" {
					continue
				}
				terminals++
				if event.Sequence == 0 {
					unsent++
					if event.WriteStatus != uint8(5) || event.Sent {
						t.Fatal("before-send typed refusal differs")
					}
					continue
				}
				sent++
				reply := returns[event.Sequence]
				want := uint8(4)
				if reply.Status == 412 {
					want = 2
				} else if reply.Status == 403 && provider == "gcp" {
					want = 5
				}
				if reply.Status == 200 && (event.Sequence == 5 || event.Sequence == 6) {
					want = 1
				}
				if !event.Sent || event.WriteStatus != uint8(want) {
					t.Fatal("native terminal changed the actual provider result", event.Sequence, event.WriteStatus, want)
				}
			}
			if terminals != 9 || sent != 8 || unsent != 1 {
				t.Fatal("native Store probe omitted or duplicated a typed result", terminals, sent, unsent)
			}
			for _, row := range []struct{ fault, response string }{
				{"lose-head-reply", "valid"},
				{"lose-head-reply-and-observation", "valid"},
				{"lose-head-reply-and-observation", "malformed"},
				{"lose-head-reply-and-observation", "truncated"},
				{"lose-head-reply-and-observation", "mismatched"},
			} {
				t.Run(row.fault+"/"+row.response, func(t *testing.T) {
					extra := fmt.Sprintf("const nativeProbeFault = %q\nconst nativeProbeResponse = %q\n", row.fault, row.response) + nativeStoreLostReplyProbe
					capture, raw := nativeStoreProbeCapture(t, root, provider, "TestNativeStoreLostReplyProbe", extra, row.fault)
					defer clear(raw)
					terminals := 0
					want := uint8(4)
					if row.response == "valid" {
						want = 1
					}
					for _, event := range capture.Events {
						if event.Kind != "store-result" {
							continue
						}
						terminals++
						if event.Operation != "head-write" || event.Sequence != 1 || !event.Sent || event.WriteStatus != want {
							t.Fatal("lost reply capture changed the validated original result", event.Operation, event.Sequence, event.Sent, event.WriteStatus, want)
						}
					}
					if terminals != 1 {
						t.Fatal("lost reply capture omitted or duplicated the original Store result", terminals)
					}
				})
			}
			t.Run("capture-failure", func(t *testing.T) {
				capture, raw := nativeStoreProbeCapture(t, root, provider, "TestNativeStoreCaptureFailureProbe", nativeStoreCaptureFailureProbe, "")
				defer clear(raw)
				for _, event := range capture.Events {
					if event.Kind == "store-result" {
						t.Fatal("failed capture retained a typed result")
					}
				}
			})
		})
	}
}

func nativeStoreProbeCapture(t *testing.T, root, provider, probeName, extra, fault string) (Capture, []byte) {
	t.Helper()
	dir := t.TempDir()
	overlay, err := BuildOverlay(root, filepath.Join(dir, "overlay"))
	if err != nil {
		t.Fatal(err)
	}
	var mapping struct{ Replace map[string]string }
	body, err := os.ReadFile(overlay.Path)
	if err != nil || json.Unmarshal(body, &mapping) != nil {
		t.Fatal("native probe overlay unavailable", err)
	}
	if provider == "gcp" {
		// The ordinary provider runner uses this same maintained source
		// to compile the complete GCP package tests.
		for _, row := range []struct{ source, target string }{
			{"tests/gcp/admission.go", "providers/gcp/zz_test_admission.go"},
			{"tests/gcpcredentials/admission.go", "providers/gcp/credentials/zz_test_admission.go"},
		} {
			support := filepath.Join(root, filepath.FromSlash(row.source))
			target := filepath.Join(root, filepath.FromSlash(row.target))
			info, err := os.Lstat(support)
			if err != nil || !info.Mode().IsRegular() {
				t.Fatal("GCP package test support unavailable", err)
			}
			if _, err := os.Lstat(target); !os.IsNotExist(err) || mapping.Replace[target] != "" {
				t.Fatal("GCP package test support would replace source")
			}
			mapping.Replace[target] = support
		}
	}
	source := nativeStoreResultProbe + extra
	if provider == "aws" {
		source = strings.Replace(source, "package gcp", "package awsprovider\nimport \"github.com/aws/aws-sdk-go-v2/aws\"", 1) + nativeAWSStoreResultProbe
	} else {
		source += nativeGCPStoreResultProbe
	}
	probe := filepath.Join(dir, "store_result_test.go")
	if err := os.WriteFile(probe, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "providers", provider, "nativeprocess_store_result_test.go")
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatal("native probe target already exists")
	}
	mapping.Replace[target] = probe
	body, err = json.Marshal(mapping)
	if err != nil || os.WriteFile(overlay.Path, body, 0600) != nil {
		t.Fatal("native probe mapping unavailable", err)
	}
	record := filepath.Join(dir, "capture")
	policyValue := Policy{Version: 1, RecordPath: record, Bucket: "fixture-bucket", MaxRequests: 16, MaxBytes: 1 << 20}
	if fault != "" {
		policyValue.Fault, policyValue.FaultOrdinal = fault, 1
		policyValue.Prefix = "fixture"
		if provider == "aws" {
			policyValue.Prefix = "enkv/domain"
		}
	}
	if probeName == "TestNativeStoreEnumerationDeleteProbe" {
		policyValue.Prefix = "fixture"
		if provider == "aws" {
			policyValue.Prefix = "enkv/domain"
		}
		policyValue.ListPrefix = policyValue.Prefix + "/" + fmt.Sprintf("%x", contract.Hash([]byte("domain"))) + "/"
	}
	policy, err := json.Marshal(policyValue)
	if err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(dir, "policy.json")
	for path, value := range map[string][]byte{record: nil, policyPath: policy} {
		if err := os.WriteFile(path, value, 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "go", nativeGoArguments("test", "-mod=readonly", "-modfile="+filepath.Join(root, "providers", provider, "telemetry_test.mod"), "-count=1", "-overlay="+overlay.Path, "-run", "^"+probeName+"$", "-v", ".")...)
	command.Dir = filepath.Join(root, "providers", provider)
	command.Env = append(os.Environ(), "GOPROXY=off", "GOSUMDB=off", "ENKV_NATIVE_PROCESS_POLICY="+policyPath)
	prepareNativeModule(t, root, command, filepath.Join(dir, "provider.mod"))
	output, err := command.CombinedOutput()
	if err != nil || !bytes.Contains(output, []byte("--- PASS: "+probeName+" (")) {
		t.Fatalf("actual provider Store observation failed: %v\n%s", err, output)
	}
	capture, err := ReadCapture(record)
	if err != nil {
		t.Fatal("native Store probe lost exact process/HTTP joins", err)
	}
	raw, err := os.ReadFile(record)
	if err != nil {
		t.Fatal("native probe exact capture image unavailable")
	}
	return capture, raw
}

const nativeStoreResultProbe = `package gcp
import("bytes";"context";"encoding/base64";"encoding/binary";"encoding/json";"errors";"fmt";"hash/crc32";"io";"net/http";"os";"sync/atomic";"testing";"time";"enkv.sh/core/contract")
type nativeProbeClose struct { io.ReadCloser; entered,release chan struct{}; calls atomic.Int32 }
func(b *nativeProbeClose)Close()error { if b.calls.Add(1)!=1{return errors.New("duplicate underlying close")};close(b.entered);<-b.release;return b.ReadCloser.Close() }
func nativeProbeTerminalCount(t *testing.T)int {t.Helper();p,err:=nativeProcessLoad();if err!=nil{t.Fatal(err)};body,err:=os.ReadFile(p.RecordPath);if err!=nil{t.Fatal(err)};defer clear(body);d:=json.NewDecoder(bytes.NewReader(body));n:=0;for{var e nativeProcessEvent;err:=d.Decode(&e);if err==io.EOF{return n};if err!=nil{t.Fatal(err)};if e.Kind=="store-result"{n++}}}
// full_only: false
func TestNativeStoreResultProbe(t *testing.T){
 ctx:=context.Background()
 for _,tc:=range []struct{status int;malformed bool;want contract.WriteStatus}{{200,true,contract.WriteUnknown},{403,false,nativeProbeDeniedStatus()},{500,false,contract.WriteUnknown},{412,false,contract.WritePrecondition},{200,false,contract.WriteAcknowledged}}{
  s:=nativeProbeStore(t,func(r *http.Request)(*http.Response,error){return nativeProbeReply(r,tc.status,tc.malformed),nil},false)
  if got:=s.CompareAndSwap(ctx,s.Descriptor().HeadKey,nativeProbeToken(),[]byte("candidate"));got.Status!=tc.want{t.Fatal("provider typed result differs",tc.status,got.Status,tc.want)}
 }
 unsent:=nativeProbeStore(t,func(*http.Request)(*http.Response,error){t.Error("credential refusal reached transport");return nil,errors.New("unexpected send")},true)
 if got:=unsent.CompareAndSwap(ctx,unsent.Descriptor().HeadKey,nativeProbeToken(),[]byte("candidate"));got.Status!=contract.WriteRefused{t.Fatal("credential refusal differs",got.Status)}
 gate:=&nativeProbeClose{entered:make(chan struct{}),release:make(chan struct{})}
 s:=nativeProbeStore(t,func(r *http.Request)(*http.Response,error){reply:=nativeProbeReply(r,200,false);gate.ReadCloser=reply.Body;reply.Body=gate;return reply,nil},false)
 before:=nativeProbeTerminalCount(t);done:=make(chan contract.WriteResult,1)
 go func(){done<-s.CompareAndSwap(ctx,s.Descriptor().HeadKey,nativeProbeToken(),[]byte("candidate"))}()
 select{case <-gate.entered:case <-time.After(5*time.Second):t.Fatal("response Close not reached")}
 premature:=nativeProbeTerminalCount(t)!=before
 close(gate.release)
 select{case result:=<-done:if result.Status!=contract.WriteAcknowledged{t.Fatal("joined response result differs",result.Status)};case <-time.After(5*time.Second):t.Fatal("Store did not join response Close")}
 if premature||gate.calls.Load()!=1||nativeProbeTerminalCount(t)!=before+1{t.Fatal("typed terminal preceded response-body Close join")}
 entered,release:=make(chan struct{},2),make(chan struct{})
 s=nativeProbeStore(t,func(r *http.Request)(*http.Response,error){body,err:=io.ReadAll(r.Body);if err!=nil{return nil,err};defer clear(body);status:=500;if bytes.Contains(body,[]byte("first-candidate")){status=412};entered<-struct{}{};<-release;return nativeProbeReply(r,status,false),nil},false)
 results:=make(chan struct{first bool;result contract.WriteResult},2)
 for _,first:=range []bool{true,false}{go func(){body:=[]byte("second-candidate");if first{body=[]byte("first-candidate")};results<-struct{first bool;result contract.WriteResult}{first,s.CompareAndSwap(ctx,s.Descriptor().HeadKey,nativeProbeToken(),body)}}()}
 admitted:=true;for i:=0;i<2;i++{select{case <-entered:case <-time.After(5*time.Second):admitted=false}}
 close(release)
 for i:=0;i<2;i++{select{case got:=<-results:want:=contract.WriteUnknown;if got.first{want=contract.WritePrecondition};if got.result.Status!=want{t.Error("concurrent provider result differs",got.result.Status,want)};case <-time.After(5*time.Second):t.Fatal("concurrent Store write did not join")}}
 if !admitted{t.Fatal("independent Store calls did not reach concurrent sends")}
 nativeProcessFinish(0)
}
func nativeProbeChecksum()string{var b [4]byte;binary.BigEndian.PutUint32(b[:],crc32.Checksum([]byte("candidate"),crc32.MakeTable(crc32.Castagnoli)));return base64.StdEncoding.EncodeToString(b[:])}
`

const nativeAWSStoreResultProbe = `
func nativeProbeDeniedStatus()contract.WriteStatus{return contract.WriteUnknown}
func nativeProbeBlockBeforeSend(s *Store){s.client.Transport=boundedTransport{host:"wrong.invalid",next:s.client.Transport}}
func nativeProbeToken()contract.Token{return contract.Token{Family:contract.AWS,Value:"\"old\""}}
func nativeProbeStore(t *testing.T, send func(*http.Request)(*http.Response,error), refused bool)*Store{t.Helper();c:=testStoreConfig();if refused{c.Credentials=aws.CredentialsProviderFunc(func(context.Context)(aws.Credentials,error){return aws.Credentials{},errors.New("credential refused")})};s,err:=newStore(c,roundTripFunc(send));if err!=nil{t.Fatal(err)};return s}
func nativeProbeReply(_ *http.Request,status int,malformed bool)*http.Response{body:="";if status!=200{body=fmt.Sprintf("<Error><Code>%s</Code></Error>",map[int]string{403:"AccessDenied",500:"InternalError",412:"PreconditionFailed"}[status])}else if malformed{body="invalid acknowledgment"};return response(status,body,nil)}
`

const nativeGCPStoreResultProbe = `
func nativeProbeDeniedStatus()contract.WriteStatus{return contract.WriteRefused}
func nativeProbeBlockBeforeSend(s *Store){s.host="wrong.invalid"}
func nativeProbeToken()contract.Token{return contract.Token{Family:contract.GCP,Value:"23"}}
func nativeProbeStore(t *testing.T, send func(*http.Request)(*http.Response,error), refused bool)*Store{t.Helper();creds:=credentialCallback(func(context.Context)(string,error){if refused{return "",errors.New("credential refused")};return "fixture-token",nil});s,err:=NewStore(context.Background(),config(makeClient(roundTripFunc(send),creds)));if err!=nil{t.Fatal(err)};return s}
func nativeProbeReply(r *http.Request,status int,malformed bool)*http.Response{body:=fmt.Sprintf("{\"bucket\":\"fixture-bucket\",\"name\":%q,\"generation\":\"24\",\"size\":\"9\",\"crc32c\":%q}","fixture/HEAD",nativeProbeChecksum());if status!=200{body=fmt.Sprintf("{\"error\":{\"code\":%d,\"errors\":[{\"reason\":%q}]}}",status,map[int]string{403:"forbidden",500:"backendError",412:"conditionNotMet"}[status])}else if malformed{body="{}"};return response(status,body)}
`

const nativeStoreLostReplyProbe = `
type nativeProbeTruncated struct{ io.ReadCloser }
func (b nativeProbeTruncated) Read(p []byte) (int, error) {
 n, err := b.ReadCloser.Read(p)
 if err == io.EOF { return n, io.ErrUnexpectedEOF }
 return n, err
}
// full_only: false
func TestNativeStoreLostReplyProbe(t *testing.T) {
 ctx := context.Background()
 calls := 0
 s := nativeProbeStore(t, func(r *http.Request) (*http.Response, error) {
  calls++
  reply := nativeProbeReply(r, http.StatusOK, nativeProbeResponse == "malformed")
  switch nativeProbeResponse {
  case "truncated":
   reply.Body = nativeProbeTruncated{reply.Body}
  case "mismatched":
   if nativeProbeToken().Family == contract.AWS {
    reply.StatusCode = http.StatusCreated
   } else {
    body, err := io.ReadAll(reply.Body)
    closeErr := reply.Body.Close()
    if err != nil || closeErr != nil { t.Fatal("controlled original reply unavailable", err, closeErr) }
    changed := bytes.Replace(body, []byte("\"size\":\"9\""), []byte("\"size\":\"8\""), 1)
    clear(body)
    reply.Body = io.NopCloser(bytes.NewReader(changed))
    reply.ContentLength = int64(len(changed))
   }
  }
  return reply, nil
 }, false)
 result := s.CompareAndSwap(ctx, s.Descriptor().HeadKey, nativeProbeToken(), []byte("candidate"))
 if result.Status != contract.WriteUnknown || result.NotSent || calls != 1 {
  t.Fatal("lost reply did not preserve one sent unknown Product result", result.Status, result.NotSent, calls)
 }
 if nativeProbeResponse == "valid" && result.Reason != contract.ReasonTransport {
  t.Fatal("controlled reply loss did not return the transport reason", result.Reason)
 }
 if nativeProbeFault == "lose-head-reply-and-observation" {
  s.Read(ctx, s.Descriptor().HeadKey, contract.MaxHeadLength)
  if calls != 1 { t.Fatal("later exact HEAD observation reached the provider", calls) }
 }
 nativeProcessFinish(0)
}
`

const nativeStoreCaptureFailureProbe = `
type nativeProbeCaptureFailure struct { io.ReadCloser; path string }
func (b nativeProbeCaptureFailure) Close() error {
 if err := b.ReadCloser.Close(); err != nil { return err }
 return os.Chmod(b.path, 0400)
}
// full_only: false
func TestNativeStoreCaptureFailureProbe(t *testing.T) {
 p, err := nativeProcessLoad()
 if err != nil { t.Fatal(err) }
 t.Cleanup(func() { if err := os.Chmod(p.RecordPath, 0600); err != nil { t.Error(err) } })
 calls := 0
 s := nativeProbeStore(t, func(r *http.Request) (*http.Response, error) {
  calls++
  reply := nativeProbeReply(r, http.StatusOK, false)
  reply.Body = nativeProbeCaptureFailure{reply.Body, p.RecordPath}
  return reply, nil
 }, false)
 got := s.CompareAndSwap(context.Background(), s.Descriptor().HeadKey, nativeProbeToken(), []byte("candidate"))
 if got.Status != contract.WriteUnknown || got.Reason != contract.ReasonConstruction || got.NotSent || calls != 1 {
  t.Fatal("failed acknowledgment capture returned success or changed send facts", got, calls)
 }
 unsent := nativeProbeStore(t, func(*http.Request) (*http.Response, error) {
  t.Error("credential refusal reached transport")
  return nil, errors.New("unexpected send")
 }, true)
 got = unsent.CompareAndSwap(context.Background(), unsent.Descriptor().HeadKey, nativeProbeToken(), []byte("candidate"))
 if got != (contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonAccess, NotSent: true}) {
  t.Fatal("failed capture changed the original unsent refusal", got)
 }
 if err := os.Chmod(p.RecordPath, 0600); err != nil { t.Fatal(err) }
 nativeProcessFinish(0)
}
`

// full_only: false
func TestNativeStoreCaptureRetainsOriginalConditions(t *testing.T) {
	root := nativeRepository(t)
	for _, provider := range []string{"aws", "gcp"} {
		t.Run(provider, func(t *testing.T) {
			capture, raw := nativeStoreProbeCapture(t, root, provider, "TestNativeStoreConditionProbe", nativeStoreConditionProbe, "")
			defer clear(raw)
			for _, forbidden := range []string{"fixture-access", "fixture-secret", "fixture-token", "condition-private-sentinel", "candidate", "Authorization"} {
				if bytes.Contains(raw, []byte(forbidden)) {
					t.Fatal("native condition evidence retained excluded input")
				}
			}
			starts, results := map[uint64]map[string]json.RawMessage{}, map[uint64]map[string]json.RawMessage{}
			decoder := json.NewDecoder(bytes.NewReader(raw))
			for range capture.Events {
				var event map[string]json.RawMessage
				if decoder.Decode(&event) != nil {
					t.Fatal("native condition capture JSON unavailable")
				}
				var kind string
				var sequence uint64
				if json.Unmarshal(event["kind"], &kind) != nil {
					t.Fatal("native condition event kind unavailable")
				}
				if kind != "http-start" && kind != "store-result" {
					continue
				}
				if json.Unmarshal(event["sequence"], &sequence) != nil || sequence == 0 {
					t.Fatal("native condition event sequence unavailable")
				}
				if kind == "http-start" {
					starts[sequence] = event
				} else {
					results[sequence] = event
				}
			}
			if len(starts) != 2 || len(results) != 2 {
				t.Fatal("native condition probe omitted original create or CAS")
			}
			for _, row := range []struct {
				name, logical, wire string
				sequence            uint64
				value, wireValue    []byte
			}{
				{"create", "absent", map[string]string{"aws": "aws-if-none-match", "gcp": "gcp-generation-match"}[provider], 1, nil, map[string][]byte{"aws": []byte("*"), "gcp": []byte("0")}[provider]},
				{"cas", "match", map[string]string{"aws": "aws-if-match", "gcp": "gcp-generation-match"}[provider], 2, map[string][]byte{"aws": []byte(`"old"`), "gcp": []byte("23")}[provider], map[string][]byte{"aws": []byte(`"old"`), "gcp": []byte("23")}[provider]},
			} {
				t.Run(row.name, func(t *testing.T) {
					for _, event := range []map[string]json.RawMessage{starts[row.sequence], results[row.sequence]} {
						var logical, wire string
						var logicalValue, wireValue []byte
						logicalOK := json.Unmarshal(event["logical_condition_kind"], &logical) == nil && logical == row.logical
						if value := event["logical_condition_value"]; len(value) != 0 && json.Unmarshal(value, &logicalValue) != nil {
							logicalOK = false
						}
						logicalOK = logicalOK && bytes.Equal(logicalValue, row.value)
						wireOK := json.Unmarshal(event["wire_condition_kind"], &wire) == nil && wire == row.wire && json.Unmarshal(event["wire_condition_value"], &wireValue) == nil && bytes.Equal(wireValue, row.wireValue)
						if !logicalOK || !wireOK {
							t.Fatalf("native original condition observation incomplete: logical=%t wire=%t", logicalOK, wireOK)
						}
					}
				})
			}
		})
	}
}

const nativeStoreConditionProbe = `
// full_only: false
func TestNativeStoreConditionProbe(t *testing.T){
 ctx:=context.Background()
 for _,create:=range []bool{true,false}{
  calls:=0
  s:=nativeProbeStore(t,func(r *http.Request)(*http.Response,error){
   calls++;r.Header.Set("X-Private-Unused","condition-private-sentinel")
   if r.URL.Host=="s3.us-east-1.amazonaws.com"{
    want:=nativeProbeToken().Value
    if create{if r.Header.Get("If-None-Match")!="*"||r.Header.Get("If-Match")!=""{t.Error("actual AWS absence condition differs")}}else if r.Header.Get("If-Match")!=want||r.Header.Get("If-None-Match")!=""{t.Error("actual AWS CAS condition differs")}
   }else{
    want:="23";if create{want="0"};values:=r.URL.Query()["ifGenerationMatch"];if len(values)!=1||values[0]!=want{t.Error("actual GCP generation condition differs")}
   }
   return nativeProbeReply(r,200,false),nil
  },false)
  var result contract.WriteResult
  if create{request,err:=contract.NewHeadCreateRequest(s.Descriptor(),[]byte("candidate"));if err!=nil{t.Fatal("exact absent HEAD request refused")};result=s.CreateHead(ctx,request)}else{result=s.CompareAndSwap(ctx,s.Descriptor().HeadKey,nativeProbeToken(),[]byte("candidate"))}
  if result.Status!=contract.WriteAcknowledged||calls!=1{t.Fatal("actual provider condition probe did not acknowledge one physical write",result.Status,calls)}
 }
 nativeProcessFinish(0)
}
`

// full_only: false
func TestNativeCaptureOriginalConditionAdmission(t *testing.T) {
	cases := []string{"aws-absent", "aws-match", "aws-256", "aws-257", "gcp-absent", "gcp-max", "gcp-overflow", "unsent", "unsent-wire", "missing-logical", "missing-wire", "wrong-wire-kind", "wrong-wire-value", "duplicate-logical-disagreement", "return-field", "read-field", "constructor-field", "source-field", "plaintext-field", "footer-field", "raw-http-only"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			value := []byte(`"old"`)
			start := Event{Kind: "http-start", Operation: "head-write", Sequence: 1, Sent: true, ObjectKeySHA256: strings.Repeat("a", 64), LogicalConditionKind: "match", LogicalConditionValue: value, WireConditionKind: "aws-if-match", WireConditionValue: append([]byte(nil), value...)}
			valid := true
			switch name {
			case "aws-absent", "gcp-absent":
				start.LogicalConditionKind, start.LogicalConditionValue = "absent", nil
				start.WireConditionKind, start.WireConditionValue = "aws-if-none-match", []byte("*")
				if name == "gcp-absent" {
					start.WireConditionKind, start.WireConditionValue = "gcp-generation-match", []byte("0")
				}
			case "aws-256", "aws-257":
				n := 256
				if name == "aws-257" {
					n = 257
					valid = false
				}
				start.LogicalConditionValue = append(append([]byte{'"'}, bytes.Repeat([]byte{0xff}, n-2)...), '"')
				start.WireConditionValue = append([]byte(nil), start.LogicalConditionValue...)
			case "gcp-max", "gcp-overflow":
				start.WireConditionKind = "gcp-generation-match"
				start.LogicalConditionValue = []byte("9223372036854775807")
				if name == "gcp-overflow" {
					start.LogicalConditionValue = []byte("9223372036854775808")
					valid = false
				}
				start.WireConditionValue = append([]byte(nil), start.LogicalConditionValue...)
			case "unsent", "unsent-wire":
				start.Sent = false
				if name == "unsent" {
					start.WireConditionKind, start.WireConditionValue = "", nil
				} else {
					valid = false
				}
			case "missing-logical":
				start.LogicalConditionKind = ""
				valid = false
			case "missing-wire":
				start.WireConditionKind, start.WireConditionValue = "", nil
				valid = false
			case "wrong-wire-kind":
				start.WireConditionKind = "arbitrary-header"
				valid = false
			case "wrong-wire-value":
				start.WireConditionValue = []byte(`"other"`)
				valid = false
			}
			terminal := start
			terminal.Kind = "store-result"
			terminal.WriteStatus = 1
			reply := Event{Kind: "http-return", Operation: start.Operation, Sequence: 1, Sent: start.Sent, ObjectKeySHA256: start.ObjectKeySHA256}
			footer := Event{Kind: "footer"}
			events := []Event{start, reply, terminal, footer}
			switch name {
			case "duplicate-logical-disagreement":
				events[2].LogicalConditionValue = []byte(`"other"`)
				events[2].WireConditionValue = []byte(`"other"`)
				valid = false
			case "return-field":
				events[1].LogicalConditionKind = "absent"
				valid = false
			case "read-field":
				events[0].Operation = "head-read"
				valid = false
			case "constructor-field":
				events = append([]Event{{Kind: "construction", Count: 1, Operation: "signer", Role: "normal", LogicalConditionKind: "absent"}}, events...)
				valid = false
			case "source-field":
				events = append([]Event{{Kind: "source-kind", Count: 1, SourceKind: "aws-sso", LogicalConditionKind: "absent"}}, events...)
				valid = false
			case "plaintext-field":
				events = append([]Event{{Kind: "plaintext", LogicalConditionKind: "absent"}}, events...)
				valid = false
			case "footer-field":
				events[3].LogicalConditionKind = "absent"
				valid = false
			case "raw-http-only":
				events = events[:2]
				events[0].LogicalConditionKind, events[0].LogicalConditionValue = "", nil
				events[0].WireConditionKind, events[0].WireConditionValue = "", nil
				events = append(events, footer)
			}
			var encoded bytes.Buffer
			for _, event := range events {
				if err := json.NewEncoder(&encoded).Encode(event); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := inspectCaptureImage(encoded.Bytes(), true); (err == nil) != valid {
				t.Fatal("original condition admission differs", err)
			}
			if name == "aws-256" {
				terminal.Sequence = ^uint64(0)
				terminal.Operation = "store-write"
				terminal.WriteStatus = 5
				image, err := json.Marshal(terminal)
				if err != nil || len(image) != 1010 {
					t.Fatal("closed maximum token line differs", len(image), err)
				}
			}
		})
	}
}

// full_only: false
func TestNativeStoreConditionRuntimeBoundsAndWhitelist(t *testing.T) {
	capture, raw := nativeStoreProbeCapture(t, nativeRepository(t), "aws", "TestNativeStoreConditionRuntimeProbe", nativeStoreConditionRuntimeProbe, "")
	defer clear(raw)
	if bytes.Contains(raw, []byte("upstream-private-sentinel")) || bytes.Contains(raw, []byte("Authorization")) || bytes.Contains(raw, []byte("X-Unused")) {
		t.Fatal("native capture copied an excluded upstream field")
	}
	starts, results := []Event{}, []Event{}
	for _, event := range capture.Events {
		if event.Kind == "http-start" {
			starts = append(starts, event)
		}
		if event.Kind == "store-result" {
			results = append(results, event)
		}
	}
	if len(starts) != 2 || len(results) != 2 {
		t.Fatal("runtime condition controls lost exact pairs")
	}
	want := append(append([]byte{'"'}, bytes.Repeat([]byte{0xff}, 254)...), '"')
	for _, event := range []Event{starts[0], results[0]} {
		if !event.Sent || event.LogicalConditionKind != "match" || event.WireConditionKind != "aws-if-match" || !bytes.Equal(event.LogicalConditionValue, want) || !bytes.Equal(event.WireConditionValue, want) {
			t.Fatal("maximum opaque token bytes changed")
		}
	}
	for _, event := range []Event{starts[1], results[1]} {
		if event.Sent || event.LogicalConditionKind != "match" || !bytes.Equal(event.LogicalConditionValue, []byte(`"old"`)) || event.WireConditionKind != "" || len(event.WireConditionValue) != 0 {
			t.Fatal("blocked send fabricated physical condition")
		}
	}
}

const nativeStoreConditionRuntimeProbe = `
// full_only: false
func TestNativeStoreConditionRuntimeProbe(t *testing.T){
 token:=append(append([]byte{'"'},bytes.Repeat([]byte{0xff},254)...),'"')
 for _,blocked:=range []bool{false,true}{
  value:=token;if blocked{value=[]byte("\"old\"")}
  ctx,scope:=nativeProcessBeginStore(context.Background(),"fixture/HEAD","store-write","match",value)
  r,err:=http.NewRequestWithContext(ctx,http.MethodPut,"https://s3.us-east-1.amazonaws.com/fixture-bucket/fixture/HEAD",bytes.NewReader([]byte("candidate")));if err!=nil{t.Fatal(err)}
  r.Header.Set("If-Match",string(value));r.Header.Set("Authorization","upstream-private-sentinel");r.Header.Set("X-Unused","upstream-private-sentinel")
  if blocked{r.ContentLength=-1}
  calls:=0
  reply,err:=nativeProcessRoundTrip(roundTripFunc(func(req *http.Request)(*http.Response,error){calls++;if req.Header.Get("Authorization")!="upstream-private-sentinel"||req.Header.Get("X-Unused")!="upstream-private-sentinel"{t.Error("observer changed unrelated headers")};return nativeProbeReply(req,200,false),nil}),r,"")
  if blocked{if err==nil||calls!=0{t.Fatal("blocked request dispatched")};if _,captureErr:=nativeProcessStoreResult(scope,5,0,false);captureErr!=nil{t.Fatal(captureErr)}}else{if err!=nil||calls!=1||reply==nil{t.Fatal("valid maximum token request refused")};if _,err=io.Copy(io.Discard,reply.Body);err!=nil{t.Fatal(err)};if err=reply.Body.Close();err!=nil{t.Fatal(err)};if _,captureErr:=nativeProcessStoreResult(scope,1,0,false);captureErr!=nil{t.Fatal(captureErr)}}
 }
 nativeProcessFinish(0)
}
`

// full_only: false
func TestNativeCaptureConditionFieldsHaveExactOwners(t *testing.T) {
	for _, field := range []string{"logical_condition_kind", "logical_condition_value", "wire_condition_kind", "wire_condition_value"} {
		t.Run(field, func(t *testing.T) {
			// Even an empty/null declared property is forbidden on a return event.
			image := `{"kind":"http-start","operation":"head-read","sequence":1}` + "\n" + `{"kind":"http-return","operation":"head-read","sequence":1,"` + field + `":null}` + "\n" + `{"kind":"footer"}` + "\n"
			if _, err := inspectCaptureImage([]byte(image), true); err == nil {
				t.Fatal("condition property accepted on unrelated event")
			}
		})
	}
}

// These expected values follow the fixed byte grammar and int64 endpoints.
// Contract parity below is supplemental; it does not supply expected values.
// full_only: false
func TestNativeCaptureConditionTokenGrammar(t *testing.T) {
	maximumAWS := append(append([]byte{'"'}, bytes.Repeat([]byte{0x80}, 254)...), '"')
	tooLongAWS := append(append([]byte{'"'}, bytes.Repeat([]byte{0x80}, 255)...), '"')
	for _, row := range []struct {
		name   string
		family contract.Family
		value  []byte
		want   bool
	}{
		{"aws-empty", contract.AWS, nil, false},
		{"aws-single-quote", contract.AWS, []byte{'"'}, false},
		{"aws-empty-quoted", contract.AWS, []byte{'"', '"'}, true},
		{"aws-unquoted", contract.AWS, []byte("etag"), false},
		{"aws-gcp-token", contract.AWS, []byte("23"), false},
		{"aws-space", contract.AWS, []byte{'"', 0x20, '"'}, false},
		{"aws-bang", contract.AWS, []byte{'"', 0x21, '"'}, true},
		{"aws-interior-quote", contract.AWS, []byte{'"', 0x22, '"'}, false},
		{"aws-hash", contract.AWS, []byte{'"', 0x23, '"'}, true},
		{"aws-backslash", contract.AWS, []byte{'"', 0x5c, '"'}, true},
		{"aws-tilde", contract.AWS, []byte{'"', 0x7e, '"'}, true},
		{"aws-del", contract.AWS, []byte{'"', 0x7f, '"'}, false},
		{"aws-raw80", contract.AWS, []byte{'"', 0x80, '"'}, true},
		{"aws-rawff", contract.AWS, []byte{'"', 0xff, '"'}, true},
		{"aws-control", contract.AWS, []byte{'"', 0x1f, '"'}, false},
		{"aws-256", contract.AWS, maximumAWS, true},
		{"aws-257", contract.AWS, tooLongAWS, false},
		{"aws-utf8", contract.AWS, []byte("\"é\""), true},
		{"aws-replacement-character", contract.AWS, []byte("\"�\""), true},
		{"aws-newline", contract.AWS, []byte{'"', 0x0a, '"'}, false},
		{"aws-unclosed", contract.AWS, []byte("\"etag"), false},
		{"gcp-empty", contract.GCP, nil, false},
		{"gcp-one", contract.GCP, []byte("1"), true},
		{"gcp-max", contract.GCP, []byte("9223372036854775807"), true},
		{"gcp-overflow", contract.GCP, []byte("9223372036854775808"), false},
		{"gcp-zero", contract.GCP, []byte("0"), false},
		{"gcp-leading-zero", contract.GCP, []byte("01"), false},
		{"gcp-plus", contract.GCP, []byte("+1"), false},
		{"gcp-minus", contract.GCP, []byte("-1"), false},
		{"gcp-leading-space", contract.GCP, []byte(" 1"), false},
		{"gcp-trailing-space", contract.GCP, []byte("1 "), false},
		{"gcp-nondigit", contract.GCP, []byte("1e1"), false},
		{"gcp-nonascii", contract.GCP, []byte("１"), false},
		{"gcp-20-digits", contract.GCP, []byte("10000000000000000000"), false},
		{"gcp-aws-token", contract.GCP, []byte("\"etag\""), false},
	} {
		t.Run(row.name, func(t *testing.T) {
			wire := "aws-if-match"
			if row.family == contract.GCP {
				wire = "gcp-generation-match"
			}
			event := Event{LogicalConditionKind: "match", LogicalConditionValue: row.value, WireConditionKind: wire, WireConditionValue: append([]byte(nil), row.value...), Sent: true}
			if nativeStoreConditionValid(event) != row.want {
				t.Fatal("capture token syntax differs from fixed expected value")
			}
			if (contract.TokenView{Family: row.family, Value: row.value}).Valid() != row.want {
				t.Fatal("supplemental contract parity differs from fixed expected value")
			}
		})
	}
}

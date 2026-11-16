package nativeprocess

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// full_only: false
func TestNativeCaptureExpectedValuesAdmitsProductEntryLimits(t *testing.T) {
	runNativeExpectedValuesRuntime(t, "TestExpectedValuesLimits")
}

// full_only: false
func TestNativePlaintextCaptureRetainsDistinctEntryIdentity(t *testing.T) {
	runNativeExpectedValuesRuntime(t, "TestPlaintextEntryIdentity")
}

func runNativeExpectedValuesRuntime(t *testing.T, name string) {
	t.Helper()
	directory := t.TempDir()
	for name, body := range map[string]string{
		"go.mod":          "module nativeexpected\n\ngo 1.27.0\n",
		"runtime.go":      runtimeSource,
		"runtime_test.go": nativeExpectedValuesTest,
	} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "go", nativeGoArguments("test", "-count=1", "-run", "^"+name+"$", ".")...)
	command.Dir = directory
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("native expected-value runtime failed: %v\n%s", err, output)
	}
}

const nativeExpectedValuesTest = `package nativeprocessruntime
import("bytes";"io";"crypto/sha256";"encoding/hex";"encoding/json";"fmt";"os";"path/filepath";"strings";"sync";"testing")
func TestExpectedValuesLimits(t *testing.T) {
 for _, tc := range []struct{count int; form string}{{128,"short"},{512,"short"},{513,"short"},{512,"long"},{512,"escaped"}} {
  count:=tc.count
  t.Run(fmt.Sprintf("%d/%s",count,tc.form),func(t *testing.T) {
   directory:=t.TempDir(); expected:=make(map[string]string,count)
   for i:=0;i<count;i++ { sum:=sha256.Sum256([]byte(fmt.Sprintf("independent value %03d",i)));name:=fmt.Sprintf("entry-%03d",i);if tc.form=="long"{name=strings.Repeat("x",253)+fmt.Sprintf("%03d",i)};if tc.form=="escaped"{name=strings.Repeat("\x01",253)+fmt.Sprintf("%03d",i)};expected[name]=hex.EncodeToString(sum[:]) }
   policy:=nativeProcessPolicy{Version:1,RecordPath:filepath.Join(directory,"capture"),MaxRequests:1,MaxBytes:1024,ExpectedSHA256:expected}
   body,err:=json.Marshal(policy);if err!=nil{t.Fatal(err)}
   path:=filepath.Join(directory,"policy.json");if os.WriteFile(path,body,0600)!=nil{t.Fatal("policy unavailable")}
   t.Setenv("ENKV_NATIVE_PROCESS_POLICY",path)
   nativeProcessState.once=sync.Once{};nativeProcessState.err=nil;nativeProcessState.policy=nativeProcessPolicy{}
   got,err:=nativeProcessLoad()
   if count<=512 { if err!=nil||len(got.ExpectedSHA256)!=count{t.Fatalf("valid Product entry count %d refused",count)};for name,sum:=range expected{if got.ExpectedSHA256[name]!=sum{t.Fatal("expected digest changed")}} } else if err==nil{t.Fatal("first excess expected-value count accepted")}
  })
 }
}
func TestPlaintextEntryIdentity(t *testing.T) {
 directory:=t.TempDir();record:=filepath.Join(directory,"capture")
 names:=[]string{"first public entry","second public entry","first public entry"}
 value:=[]byte("same independent synthetic plaintext")
 digest:=sha256.Sum256(value)
 expected:=map[string]string{names[0]:hex.EncodeToString(digest[:]),names[1]:hex.EncodeToString(digest[:])}
 policy:=nativeProcessPolicy{Version:1,RecordPath:record,MaxRequests:1,MaxBytes:1024,ExpectedSHA256:expected}
 body,err:=json.Marshal(policy);if err!=nil{t.Fatal(err)}
 path:=filepath.Join(directory,"policy.json")
 if os.WriteFile(path,body,0600)!=nil||os.WriteFile(record,nil,0600)!=nil{t.Fatal("identity fixture unavailable")}
 t.Setenv("ENKV_NATIVE_PROCESS_POLICY",path)
 nativeProcessState.once=sync.Once{};nativeProcessState.err=nil;nativeProcessState.policy=nativeProcessPolicy{}
 for _,name:=range names{nativeProcessPlaintext(name,value)}
 nativeProcessFinish(0)
 body,err=os.ReadFile(record);if err!=nil{t.Fatal("identity capture unavailable")}
 for _,name:=range names {if bytes.Contains(body,[]byte(name)){t.Fatal("plaintext capture exposed raw entry name")}}
 if bytes.Contains(body,value){t.Fatal("plaintext capture exposed plaintext")}
 decoder:=json.NewDecoder(bytes.NewReader(body))
 for _,name:=range names{
  var row map[string]any
  if decoder.Decode(&row)!=nil{t.Fatal("plaintext identity event missing")}
  sum:=sha256.Sum256([]byte(name))
  if row["kind"]!="plaintext"||row["count"]!=float64(1)||row["matched"]!=true||row["entry_sha256"]!=hex.EncodeToString(sum[:]){t.Fatal("plaintext event lost stable public entry-name hash")}
 }
 var footer map[string]any
 if decoder.Decode(&footer)!=nil||footer["kind"]!="footer"||decoder.Decode(new(any))!=io.EOF{t.Fatal("plaintext identity capture footer differs")}
}
`

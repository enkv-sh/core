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
func TestNativeCaptureLabelsExactGCPEncryptionKeyParents(t *testing.T) {
	dir := t.TempDir()
	record := filepath.Join(dir, "capture")
	policy, err := json.Marshal(Policy{Version: 1, RecordPath: record, MaxRequests: 4, MaxBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{
		"go.mod":          []byte("module nativekeyroles\n\ngo 1.27.0\n"),
		"runtime.go":      []byte(runtimeSource),
		"runtime_test.go": []byte(nativeGCPParentRoleTest),
		"policy.json":     policy,
		"capture":         nil,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "go", nativeGoArguments("test", "-count=1", "-run", "^TestGCPEncryptionKeyParentRoles$", ".")...)
	command.Dir = dir
	command.Env = append(os.Environ(), "ENKV_NATIVE_PROCESS_POLICY="+filepath.Join(dir, "policy.json"))
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("native encryption metadata role capture differs: %v\n%s", err, output)
	}
	capture, err := ReadCapture(record)
	if err != nil || len(capture.Events) != 9 {
		t.Fatal("metadata role capture lost exact event pairs and footer", err)
	}
	for i, role := range []string{"successor-private", "authority", "recovery-private", "recipient-private"} {
		start, returned := capture.Events[2*i], capture.Events[2*i+1]
		if start.Kind != "http-start" || returned.Kind != "http-return" || start.Operation != "kms-public" || returned.Operation != start.Operation || start.Role != role || returned.Role != role || !start.Sent || !returned.Sent || returned.Status != 200 {
			t.Fatal("parent metadata request lost its exact nominated encryption role", i)
		}
	}
}

const nativeGCPParentRoleTest = `package nativeprocessruntime

import (
 "bytes"
 "context"
 "encoding/json"
 "io"
 "net/http"
 "strings"
 "testing"
)

type parentRoleTransport struct{}
func (parentRoleTransport) RoundTrip(r *http.Request) (*http.Response, error) {
 return &http.Response{StatusCode:200, Header:make(http.Header), ContentLength:2, Body:io.NopCloser(strings.NewReader("{}")), Request:r}, nil
}

func TestGCPEncryptionKeyParentRoles(t *testing.T) {
 if _,err:=nativeProcessLoad();err!=nil{t.Fatal(err)}
 const prefix="projects/fixture-project/locations/us-central1/keyRings/fixture/cryptoKeys/"
 const suffix="/cryptoKeyVersions/1"
 const host="https://us-central1-cloudkms.googleapis.com/v1/"
 const query="?alt=json&prettyPrint=false"
 nativeProcessState.policy.NormalSigner=prefix+"normal"+suffix
 nativeProcessState.policy.SuccessorSigner=prefix+"next-signer"+suffix
 nativeProcessState.policy.SuccessorKEK=prefix+"next-kek"+suffix
 nativeProcessState.policy.AuthorityKEK=prefix+"authority"+suffix
 nativeProcessState.policy.RecoverySigner=prefix+"recovery-signer"+suffix
 nativeProcessState.policy.RecoveryKEK=prefix+"recovery-kek"+suffix
 nativeProcessState.policy.RecipientKEK=prefix+"recipient"+suffix
 original:=nativeProcessState.policy
 roles:=[]struct{name,selector string}{
  {"normal",original.NormalSigner},{"successor",original.SuccessorSigner},
  {"successor-private",original.SuccessorKEK},{"authority",original.AuthorityKEK},
  {"recovery-signing",original.RecoverySigner},{"recovery-private",original.RecoveryKEK},
  {"recipient-private",original.RecipientKEK},
 }
 for _,role:=range roles{
  if nativeProcessRole(role.selector)!=role.name{t.Error("construction selector role changed",role.name)}
  for _,end:=range []string{"","/publicKey",":asymmetricSign",":asymmetricDecrypt"}{
   request,err:=http.NewRequest("GET",host+role.selector+end+query,nil);if err!=nil{t.Fatal(err)}
   if nativeProcessGCPRole(request)!=role.name{t.Error("exact full-version role changed",role.name,end)}
  }
 }
 for _,role:=range roles{
  parent:=strings.TrimSuffix(role.selector,suffix)
  request,err:=http.NewRequest("GET",host+parent+query,nil);if err!=nil{t.Fatal(err)}
  want:=role.name
  if role.name=="normal"||role.name=="successor"||role.name=="recovery-signing"{want="ordinary"}
  if got:=nativeProcessGCPRole(request);got!=want{t.Errorf("parent role=%s want=%s got=%s",role.name,want,got)}
  // Pinned googleapi.Expand writes both Path and RawPath; transport clones them.
  request.URL.RawPath=request.URL.Path
  cloned:=request.Clone(context.Background())
  if cloned.URL.RawPath==""||cloned.URL.RawPath!=cloned.URL.Path||nativeProcessGCPRole(cloned)!=want{t.Error("canonical SDK-expanded cloned parent lost its role",role.name)}
 }
 parent:=prefix+"next-kek"
 nativeProcessState.policy.SuccessorKEK=parent+"/cryptoKeyVersions/9223372036854775807"
 maximum,_:=http.NewRequest("GET",host+parent+query,nil)
 maximum.URL.RawPath=maximum.URL.Path
 if got:=nativeProcessGCPRole(maximum.Clone(context.Background()));got!="successor-private"{t.Error("canonical int64 maximum version lost its parent role",got)}
 nativeProcessState.policy=original
 cases:=[]struct{name,method,url string}{
  {"post-parent","POST",host+parent+query},
  {"http-host","GET",strings.Replace(host,"https:","http:",1)+parent+query},
  {"foreign-host","GET",strings.Replace(host,"us-central1-cloudkms.googleapis.com","foreign.invalid",1)+parent+query},
  {"lookalike-host","GET",strings.Replace(host,"googleapis.com","googleapis.com.example",1)+parent+query},
  {"wrong-region-host","GET",strings.Replace(host,"us-central1-cloudkms","us-east1-cloudkms",1)+parent+query},
  {"port","GET",strings.Replace(host,".com/",".com:443/",1)+parent+query},
  {"userinfo","GET",strings.Replace(host,"https://","https://user@",1)+parent+query},
  {"fragment","GET",host+parent+query+"#private"},
  {"extra-query","GET",host+parent+query+"&fields=name"},
  {"duplicate-query","GET",host+parent+query+"&alt=json"},
  {"wrong-query","GET",host+parent+"?alt=media&prettyPrint=false"},
  {"query-decode-damage","GET",host+parent+"?alt=%zz&prettyPrint=false"},
  {"encoded-query-key","GET",host+parent+"?%61lt=json&prettyPrint=false"},
  {"wrong-project","GET",host+strings.Replace(parent,"fixture-project","other-project",1)+query},
  {"wrong-location","GET",host+strings.Replace(parent,"us-central1","us-east1",1)+query},
  {"wrong-ring","GET",host+strings.Replace(parent,"keyRings/fixture","keyRings/other",1)+query},
  {"sibling-key","GET",host+parent+"-other"+query},
  {"sibling-version","GET",host+parent+"/cryptoKeyVersions/2"+query},
  {"version-prefix","GET",host+parent+"/cryptoKeyVersions"+query},
  {"parent-public-suffix","GET",host+parent+"/publicKey"+query},
  {"parent-private-action","POST",host+parent+":asymmetricDecrypt"+query},
  {"encoded-alias","GET",host+strings.Replace(parent,"next-kek","%6eext-kek",1)+query},
  {"path-traversal","GET",host+prefix+"other/../next-kek"+query},
  {"trailing-slash","GET",host+parent+"/"+query},
 }
 for _,tc:=range cases{t.Run(tc.name,func(t *testing.T){request,err:=http.NewRequest(tc.method,tc.url,nil);if err!=nil{t.Fatal(err)};if got:=nativeProcessGCPRole(request);got!="ordinary"{t.Error("nonexact metadata request inherited a role",got)}})}
 for _,selector:=range []string{parent+"/cryptoKeyVersions/0",parent+"/cryptoKeyVersions/01",parent+"/cryptoKeyVersions/current",parent+"/cryptoKeyVersions/-1",parent+"/cryptoKeyVersions/9223372036854775808",parent+"/cryptoKeyVersions/99999999999999999999999999999999999",parent+"/cryptoKeyVersions/1/extra",parent+"/cryptoKeyVersions/1?other",strings.Replace(parent,"next-kek","..",1)+suffix}{
  nativeProcessState.policy.SuccessorKEK=selector
  request,err:=http.NewRequest("GET",host+strings.Split(selector,"/cryptoKeyVersions/")[0]+query,nil);if err!=nil{t.Fatal(err)}
  if got:=nativeProcessGCPRole(request);got!="ordinary"{t.Error("malformed nominated selector attributed its parent",got)}
 }
 nativeProcessState.policy=original
 withBody,_:=http.NewRequest("GET",host+parent+query,strings.NewReader("{}"))
 if got:=nativeProcessGCPRole(withBody);got!="ordinary"{t.Error("GET with a body inherited metadata role",got)}
 if err:=withBody.Body.Close();err!=nil{t.Fatal(err)}
 for _,change:=range []func(*http.Request){
  func(r *http.Request){r.ContentLength=1},
  func(r *http.Request){r.TransferEncoding=[]string{"chunked"}},
  func(r *http.Request){r.Host="other.invalid"},
 }{request,_:=http.NewRequest("GET",host+parent+query,nil);change(request);if got:=nativeProcessGCPRole(request);got!="ordinary"{t.Error("nonempty or differently hosted metadata request inherited role",got)}}
 for _,same:=range []string{original.SuccessorKEK,strings.TrimSuffix(original.SuccessorKEK,"1")+"2"}{
  nativeProcessState.policy.RecoveryKEK=same
  request,_:=http.NewRequest("GET",host+parent+query,nil)
  if got:=nativeProcessGCPRole(request);got!="ordinary"{t.Error("ambiguous parent silently chose a role",got)}
 }
 nativeProcessState.policy=original
 nativeProcessState.policy.NormalSigner=strings.TrimSuffix(original.SuccessorKEK,"1")+"2"
 request,_:=http.NewRequest("GET",host+parent+query,nil)
 if got:=nativeProcessGCPRole(request);got!="ordinary"{t.Error("mixed signing/encryption parent silently chose a role",got)}
 nativeProcessState.policy=original
 // AWS still attributes only the exact KeyId from its bounded request body.
 for _,key:=range []string{original.SuccessorKEK,parent,"/v1/"+parent}{
  raw,_:=json.Marshal(struct{KeyID string ` + "`" + `json:"KeyId"` + "`" + `}{key})
  aws,_:=http.NewRequest("POST","https://kms.us-east-1.amazonaws.com/",bytes.NewReader(raw));aws.Header.Set("X-Amz-Target","TrentService.GetPublicKey")
  got,err:=nativeProcessPrepareAWS(aws);if err!=nil{t.Fatal(err)}
  want:="ordinary";if key==original.SuccessorKEK{want="successor-private"}
  if got!=want{t.Error("AWS KeyId attribution changed",got,want)}
  if err:=aws.Body.Close();err!=nil{t.Fatal(err)}
 }
 const arn="arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000001"
 nativeProcessState.policy.AuthorityKEK=arn
 if nativeProcessRole(arn)!="authority"||nativeProcessRole(arn+"-other")!="ordinary"{t.Error("AWS exact ARN or sibling attribution changed")}
 nativeProcessState.policy=original
 for _,role:=range roles{
  if role.name!="successor-private"&&role.name!="authority"&&role.name!="recovery-private"&&role.name!="recipient-private"{continue}
  request,_:=http.NewRequest("GET",host+strings.TrimSuffix(role.selector,suffix)+query,nil)
  request.URL.RawPath=request.URL.Path
  request=request.Clone(context.Background())
  response,err:=nativeProcessRoundTrip(parentRoleTransport{},request,nativeProcessGCPRole(request));if err!=nil{t.Fatal(err)}
  body,err:=io.ReadAll(response.Body);closeErr:=response.Body.Close();if err!=nil||closeErr!=nil||string(body)!="{}"{t.Fatal("capture changed parent metadata response",err,closeErr)}
 }
 nativeProcessFinish(0)
}
`

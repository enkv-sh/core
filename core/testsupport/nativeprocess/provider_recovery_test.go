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
func TestNativeAWSWriteReasonControlsCoreRecovery(t *testing.T) {
	nativeProviderCoreProbe(t, "TestAWSProviderReasonCoreRecoveryProbe")
}

// full_only: false
func TestNativeGCPNoSendKeepsGCDispatchSpent(t *testing.T) {
	nativeProviderCoreProbe(t, "TestGCPProviderNoSendGCProbe")
}

func nativeProviderCoreProbe(t *testing.T, name string) {
	t.Helper()
	root, directory := nativeRepository(t), t.TempDir()
	source := filepath.Join(directory, "provider_test.go")
	if err := os.WriteFile(source, []byte(nativeProviderCoreSource), 0600); err != nil {
		t.Fatal(err)
	}
	mapping := map[string]string{filepath.Join(root, "core", "nativeprocess_provider_recovery_test.go"): source}
	for _, row := range []struct{ source, target string }{
		{"tests/crypto/admission.go", "crypto/zz_test_admission.go"},
		{"tests/gcp/admission.go", "providers/gcp/zz_test_admission.go"},
		{"tests/gcpcredentials/admission.go", "providers/gcp/credentials/zz_test_admission.go"},
	} {
		target := filepath.Join(root, filepath.FromSlash(row.target))
		if _, err := os.Lstat(target); !os.IsNotExist(err) {
			t.Fatal("native provider proof would replace source")
		}
		mapping[target] = filepath.Join(root, filepath.FromSlash(row.source))
	}
	overlayBody, err := json.Marshal(struct{ Replace map[string]string }{mapping})
	if err != nil {
		t.Fatal(err)
	}
	overlay := filepath.Join(directory, "overlay.json")
	if err := os.WriteFile(overlay, overlayBody, 0600); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(directory, "input.mod")
	definition, err := os.ReadFile(filepath.Join(root, "compositions", "full", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Count(definition, []byte("module enkv.sh/compositions/full\n")) != 1 || bytes.Count(definition, []byte("\tenkv.sh/core v0.1.1\n")) != 1 {
		t.Fatal("pinned full-composition closure differs")
	}
	definition = bytes.Replace(definition, []byte("module enkv.sh/compositions/full\n"), []byte("module enkv.sh/core\n"), 1)
	definition = bytes.Replace(definition, []byte("\tenkv.sh/core v0.1.1\n"), nil, 1)
	if err := os.WriteFile(input, definition, 0600); err != nil {
		t.Fatal(err)
	}
	sums, err := os.ReadFile(filepath.Join(root, "compositions", "full", "go.sum"))
	if err != nil || os.WriteFile(strings.TrimSuffix(input, ".mod")+".sum", sums, 0600) != nil {
		t.Fatal("pinned provider proof sums unavailable", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "go", nativeGoArguments("test", "-mod=readonly", "-modfile="+input, "-overlay="+overlay, "-count=1", "-run", "^"+name+"$", "-v", ".")...)
	command.Dir = filepath.Join(root, "core")
	command.Env = append(os.Environ(), "GOPROXY=off", "GOSUMDB=off", "GOWORK=off", "GOTOOLCHAIN=local")
	prepareNativeModule(t, root, command, filepath.Join(directory, "core.mod"))
	output, err := command.CombinedOutput()
	if err != nil || !bytes.Contains(output, []byte("--- PASS: "+name+" (")) {
		t.Fatalf("joined provider/Core proof failed: %v\n%s", err, output)
	}
}

const nativeProviderCoreSource = `package core

import (
 "bytes"
 "context"
 "crypto/ecdsa"
 "crypto/elliptic"
 "crypto/rand"
 "crypto/tls"
 "crypto/x509"
 "crypto/x509/pkix"
 "errors"
 "fmt"
 "io"
 "math/big"
 "net"
 "net/http"
 "net/http/httptest"
 "strconv"
 "sync/atomic"
 "testing"
 "time"

 "enkv.sh/core/contract"
 awsprovider "enkv.sh/providers/aws"
 gcpprovider "enkv.sh/providers/gcp"
 "github.com/aws/aws-sdk-go-v2/aws"
)

type nativeAWSRecoveryStore struct {
 *observationSelectionStore
 provider *awsprovider.Store
}
func (s *nativeAWSRecoveryStore) CompareAndSwap(ctx context.Context,key string,token contract.Token,body []byte) contract.WriteResult {
 s.sends++
 return s.provider.CompareAndSwap(ctx,key,token,body)
}

func nativeAWSRecoveryTransport(t *testing.T, handler http.Handler) *http.Transport {
 t.Helper()
 key,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader)
 if err!=nil {t.Fatal(err)}
 template:=&x509.Certificate{SerialNumber:big.NewInt(1),Subject:pkix.Name{CommonName:"s3.us-east-1.amazonaws.com"},DNSNames:[]string{"s3.us-east-1.amazonaws.com"},NotBefore:time.Now().Add(-time.Minute),NotAfter:time.Now().Add(time.Hour),KeyUsage:x509.KeyUsageDigitalSignature,ExtKeyUsage:[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
 certificate,err:=x509.CreateCertificate(rand.Reader,template,template,&key.PublicKey,key)
 if err!=nil {t.Fatal(err)}
 parsed,err:=x509.ParseCertificate(certificate)
 if err!=nil {t.Fatal(err)}
 roots:=x509.NewCertPool();roots.AddCert(parsed)
 server:=httptest.NewUnstartedServer(handler)
 server.TLS=&tls.Config{Certificates:[]tls.Certificate{{Certificate:[][]byte{certificate},PrivateKey:key}}}
 server.StartTLS();t.Cleanup(server.Close)
 transport:=&http.Transport{TLSClientConfig:&tls.Config{RootCAs:roots},TLSHandshakeTimeout:time.Second,ResponseHeaderTimeout:time.Second,DialContext:func(ctx context.Context,network,address string)(net.Conn,error){
  if network!="tcp" || address!="s3.us-east-1.amazonaws.com:443" {return nil,errors.New("unexpected provider address")}
  return (&net.Dialer{}).DialContext(ctx,"tcp",server.Listener.Addr().String())
 }}
 t.Cleanup(transport.CloseIdleConnections)
 return transport
}

func TestAWSProviderReasonCoreRecoveryProbe(t *testing.T) {
 for _,condition:=range []string{"received-invalid-request","received-slow-down","transport-loss"} {
  t.Run(condition,func(t *testing.T){
   before,first,_,memory,result:=observationPreparedSelectionForFamily(t,contract.AWS)
   if first==nil || result.Outcome!=ObservedCurrent {t.Fatal("valid AWS candidate unavailable",result)}
   selected,result:=before.selectCandidate(t.Context(),first)
   if selected==nil || result.Outcome!=ObservedCurrent {t.Fatal("selected AWS predecessor unavailable",result)}
   candidate,_,result:=observationPrepareNextSelection(t,selected,104000,"changed","enabled")
   if candidate==nil || result.Outcome!=ObservedCurrent {t.Fatal("next AWS candidate unavailable",result)}
   memory.sends=0
   expectedBody:=bytes.Clone(candidate.body);expectedToken:=selected.token
   var calls atomic.Int32
   transport:=nativeAWSRecoveryTransport(t,http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
    calls.Add(1)
    body,err:=io.ReadAll(r.Body)
    if err!=nil || r.Method!=http.MethodPut || r.URL.Path!="/fixture-bucket/fixture/HEAD" || r.Header.Get("If-Match")!=expectedToken.Value || !bytes.Equal(body,expectedBody){t.Error("physical conditional request changed",err)}
    if condition=="transport-loss" {connection,_,err:=w.(http.Hijacker).Hijack();if err!=nil{t.Error(err);return};if err:=connection.Close();err!=nil{t.Error(err)};return}
    reply,status:="<Error><Code>InvalidRequest</Code></Error>",http.StatusBadRequest
    if condition=="received-slow-down" {reply,status="<Error><Code>SlowDown</Code></Error>",http.StatusServiceUnavailable}
    w.Header().Set("Content-Type","application/xml");w.Header().Set("Content-Length",strconv.Itoa(len(reply)));w.WriteHeader(status)
    if _,err:=io.WriteString(w,reply);err!=nil{t.Error(err)}
   }))
   provider,err:=awsprovider.NewStore(awsprovider.StoreConfig{Region:"us-east-1",Bucket:"fixture-bucket",ExpectedBucketOwner:"123456789012",Prefix:"fixture",Domain:selected.admission.domain,CredentialRoute:contract.ID{1},Credentials:aws.CredentialsProviderFunc(func(context.Context)(aws.Credentials,error){return aws.Credentials{AccessKeyID:"fixture-access",SecretAccessKey:"fixture-secret"},nil}),Transport:transport,Timeout:10*time.Second})
   if err!=nil {t.Fatal(err)}
   store:=&nativeAWSRecoveryStore{observationSelectionStore:memory,provider:provider}
   selected.store=store;memory.commit=false
   ctx,cancel:=context.WithTimeout(t.Context(),10*time.Second);defer cancel()
   out:=selected.Select(ctx,candidate)
   expectedCalls:=1
   if condition=="transport-loss" || condition=="received-slow-down"{expectedCalls=3}
   if out.Outcome!=UnresolvedCommit || !out.CommitMayHaveOccurred || out.RequestedRevision!=candidate.head.Core.Revision || out.ObservedRevision!=selected.head.Core.Revision || out.Evidence!=AuthenticatedClosure || store.sends!=expectedCalls || int(calls.Load())!=expectedCalls {
    t.Fatal("provider reason changed Core recovery or erased prior uncertainty",condition,out,store.sends,calls.Load(),expectedCalls)
   }
  })
 }
}

type nativeGCRefusedCredentials struct { calls int }
func (c *nativeGCRefusedCredentials) Token(context.Context)(string,error){c.calls++;return "",errors.New("controlled credential refusal")}

func TestGCPProviderNoSendGCProbe(t *testing.T) {
 t.Setenv("GOOGLE_API_USE_CLIENT_CERTIFICATE","false");t.Setenv("EXPERIMENTAL_GOOGLE_API_USE_S2A","false")
 state,store,input,plan,encoded:=gcExecutionFixture(t)
 credentials:=&nativeGCRefusedCredentials{}
 physical:=0
 client,err:=gcpprovider.NewLocalResponderClient(&http.Transport{DialContext:func(context.Context,string,string)(net.Conn,error){physical++;return nil,errors.New("unexpected physical send")}},credentials)
 if err!=nil{t.Fatal(err)}
 configuration:=store.StoreConfiguration()
 provider,err:=gcpprovider.NewStore(t.Context(),gcpprovider.StoreConfig{Client:client,Domain:configuration.DomainID,Region:configuration.Region,Endpoint:"https://storage."+configuration.Region+".rep.googleapis.com/storage/v1/",Bucket:configuration.Bucket,Prefix:configuration.PrefixBeforeHEAD,CredentialRoute:"native-gc-refused-route"})
 if err!=nil{t.Fatal(err)}
 callbacks:=0;var actual contract.WriteResult
 ctx:=gcReadContext(t)
 store.onDelete=func(key string,token contract.Token)*contract.WriteResult {callbacks++;actual=provider.DeleteIfToken(ctx,key,token);return &actual}
 engine,_:=gcExecutionEngine(t,state,store,input)
 out:=engine.ApplyPlan(ctx,GCApplyPlanRequest{RequestNonce:gcTestID("native-provider-access"),EncodedPlan:encoded})
 expected:=contract.WriteResult{Status:contract.WriteRefused,Reason:contract.ReasonAccess,NotSent:true}
 if actual!=expected || callbacks!=1 || credentials.calls!=1 || physical!=0 || out.Validate()!=nil || out.Payload==nil || len(out.Payload.Targets)!=1 {t.Fatal("actual provider refusal lost positive no-send or GC result",actual,callbacks,credentials.calls,physical,out)}
 row:=out.Payload.Targets[0]
 token,err:=GCTargetEffectToken(row)
 if err!=nil || token!="not-started" || row.DeleteResult!=actual || row.Selected.Consumed!=1 || row.Selected.Disposition!=contract.GCTargetTerminalFailure || !row.Selected.EvidenceDigest.IsZero(){t.Fatal("GC merged no-send with future dispatch rights",row,token,err)}
 if err:=engine.Close();err!=nil{t.Fatal(err)}
 next,_:=gcExecutionEngine(t,state,store,input)
 continued:=next.Continue(ctx,GCContinueRequest{RequestNonce:gcTestID("native-provider-access-continuation"),OperationID:plan.OperationID})
 if continued.Validate()!=nil || callbacks!=1 || credentials.calls!=1 || physical!=0 || continued.Payload==nil || continued.Payload.Targets[0].Selected.Consumed!=1 || continued.Payload.Targets[0].Selected.Disposition==contract.GCTargetRetryableNotSent {t.Fatal("GC restored the consumed callback",fmt.Sprint(continued),callbacks,credentials.calls,physical)}
}
`

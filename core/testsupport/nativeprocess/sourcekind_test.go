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
func TestNativeOutputObservationDistinguishesAbsentFromInvalidPolicy(t *testing.T) {
	directory := t.TempDir()
	for name, body := range map[string]string{"go.mod": "module nativeoutputpolicy\n\ngo 1.27.0\n", "runtime.go": runtimeSource + sourceKindSource, "runtime_test.go": nativeOutputPolicyTest} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, condition := range []string{"absent", "empty", "invalid"} {
		t.Run(condition, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			command := exec.CommandContext(ctx, "go", nativeGoArguments("test", "-count=1", "-run", "^TestOutputPolicy$", ".")...)
			command.Dir = directory
			for _, setting := range os.Environ() {
				if !strings.HasPrefix(setting, "ENKV_NATIVE_PROCESS_POLICY=") {
					command.Env = append(command.Env, setting)
				}
			}
			command.Env = append(command.Env, "NATIVE_OUTPUT_POLICY_CASE="+condition)
			switch condition {
			case "empty":
				command.Env = append(command.Env, "ENKV_NATIVE_PROCESS_POLICY=")
			case "invalid":
				command.Env = append(command.Env, "ENKV_NATIVE_PROCESS_POLICY="+filepath.Join(directory, "missing-policy"))
			}
			if body, err := command.CombinedOutput(); err != nil {
				t.Fatalf("optional output policy admission differs: %v\n%s", err, body)
			}
		})
	}
}

const nativeOutputPolicyTest = `package nativeprocessruntime
import("context";"net/http";"os";"testing")
func TestOutputPolicy(t *testing.T){
 absent:=os.Getenv("NATIVE_OUTPUT_POLICY_CASE")=="absent";client:=&http.Client{}
 actual,clientErr:=nativeProcessOutputCredentialClient(client)
 errs:=[]error{clientErr,nativeProcessObserveOutputAWS("SSOProvider",true,false),nativeProcessOutputAWSEndpoints(context.Background(),nil,nil),nativeProcessObserveOutputADC([]byte("{}"),"")}
 for _,err:=range errs{if (err==nil)!=absent{t.Fatal("present invalid policy bypassed observation or absence changed ordinary plugin behavior")}}
 if absent&&actual!=client{t.Fatal("absent policy replaced the ordinary credential client")}
}
`

// full_only: false
func TestNativeStandardSourceRequiresExactKindAndOfficialService(t *testing.T) {
	dir := t.TempDir()
	record := filepath.Join(dir, "capture")
	policy := Policy{Version: 1, RecordPath: record, MaxRequests: 1, MaxBytes: 1024, RequireStandardSource: true, ExpectedSourceKind: "aws-sso"}
	encoded, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(dir, "policy.json")
	for name, body := range map[string][]byte{"go.mod": []byte("module nativesource\n\ngo 1.27.0\n"), "runtime.go": []byte(runtimeSource + sourceKindSource), "runtime_test.go": []byte(nativeSourceKindTest), "policy.json": encoded, "capture": nil} {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", nativeGoArguments("test", "-count=1", "-run", "^TestStandardSourceKind$", ".")...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "ENKV_NATIVE_PROCESS_POLICY="+policyPath)
	if body, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("native standard source observer failed: %v\n%s", err, body)
	}
	capture, err := ReadCapture(record)
	if err != nil || len(capture.Events) != 16 || capture.Events[0].Matched || !capture.Events[1].Matched || capture.Events[2].Matched || capture.Events[3].Matched || capture.Events[3].SourceKind != "aws-assume-role" {
		t.Fatal("fixed source observations differ", err)
	}
	for i, matched := range []bool{true, false, false, false, false} {
		if capture.Events[10+i].Matched != matched {
			t.Fatal("ADC source selection or refusal observation differs", i)
		}
	}
}

const nativeSourceKindTest = `package nativeprocessruntime
import("encoding/json";"bytes";"net/http";"os";"strings";"testing")
func TestStandardSourceKind(t *testing.T){
 if nativeProcessSourceKind("aws-sso",false)==nil {t.Fatal("different AWS source met standard source requirement")}
 if nativeProcessSourceKind("aws-sso",true)!=nil {t.Fatal("exact source refused")}
 if nativeProcessSourceKind("gcp-user-adc",true)==nil || nativeProcessSourceKind("aws-assume-role",true)==nil {t.Fatal("different standard mode accepted")}
 for _,kind:=range []string{"aws-sso","aws-assume-role","aws-shared-credentials","gcp-user-adc","gcp-impersonated-adc","gcp-service-account-adc"}{nativeProcessState.policy.ExpectedSourceKind=kind;if nativeProcessSourceKind(kind,true)!=nil{t.Fatal("selected standard source refused",kind)}}
 if nativeProcessSourceKind("private source detail",true)==nil {t.Fatal("open source enumeration accepted")}
 for _,kind:=range []string{"service_account","external_account_authorized_user","impersonated_service_account",""}{ if nativeProcessADCSourceKind([]byte("{\"type\":\""+kind+"\"}"))!=""{t.Fatal("non-user ADC accepted")} }
 raw:=[]byte("{\"type\":\"authorized_user\",\"refresh_token\":\"do-not-record\"}");before:=bytes.Clone(raw)
 if nativeProcessADCSourceKind(raw)!="gcp-user-adc"||!bytes.Equal(raw,before){t.Fatal("selected ADC type or SDK ownership changed")}
 impersonated:=[]byte(` + "`" + `{"type":"impersonated_service_account","service_account_impersonation_url":"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/test@example.iam.gserviceaccount.com:generateAccessToken","source_credentials":{"type":"authorized_user","refresh_token":"do-not-record"}}` + "`" + `)
 if nativeProcessADCSourceKind(impersonated)!="gcp-impersonated-adc" {t.Fatal("impersonated user ADC refused")}
 for _,bad:=range []string{"http://iamcredentials.googleapis.com/", "https://iamcredentials.googleapis.com.example/v1/projects/-/serviceAccounts/test@example.iam.gserviceaccount.com:generateAccessToken", "https://iamcredentials.googleapis.com:443/v1/projects/-/serviceAccounts/test@example.iam.gserviceaccount.com:generateAccessToken", "https://user@iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/test@example.iam.gserviceaccount.com:generateAccessToken"}{
  var selected map[string]any;if json.Unmarshal(impersonated,&selected)!=nil{t.Fatal("fixture")};selected["service_account_impersonation_url"]=bad;raw,_:=json.Marshal(selected);if nativeProcessADCSourceKind(raw)!=""{t.Fatal("nonofficial impersonation endpoint accepted")}
 }
 for _,kind:=range []string{"service_account","external_account","impersonated_service_account",""}{var selected map[string]any;if json.Unmarshal(impersonated,&selected)!=nil{t.Fatal("fixture")};selected["source_credentials"]=map[string]any{"type":kind};raw,_:=json.Marshal(selected);if nativeProcessADCSourceKind(raw)!=""{t.Fatal("non-user impersonation source accepted")}}
 serviceAccount:=[]byte(` + "`" + `{"type":"service_account","token_uri":"https://oauth2.googleapis.com/token","universe_domain":"googleapis.com","private_key":"do-not-record"}` + "`" + `)
 if nativeProcessADCSourceKind(serviceAccount)!="gcp-service-account-adc"{t.Fatal("standard service account ADC refused")}
 for _,bad:=range []string{"", "http://oauth2.googleapis.com/token", "https://oauth2.googleapis.com:443/token", "https://user@oauth2.googleapis.com/token", "https://oauth2.googleapis.com/token?target=other", "https://oauth2.googleapis.com.example/token"}{
  var selected map[string]any;if json.Unmarshal(serviceAccount,&selected)!=nil{t.Fatal("fixture")};selected["token_uri"]=bad;raw,_:=json.Marshal(selected);if nativeProcessADCSourceKind(raw)!=""{t.Fatal("nonofficial service account token endpoint accepted")}
 }
 for _,universe:=range []string{"", "googleapis.com", "other-universe.invalid"}{
  var selected map[string]any;if json.Unmarshal(serviceAccount,&selected)!=nil{t.Fatal("fixture")};selected["universe_domain"]=universe;raw,_:=json.Marshal(selected);if (nativeProcessADCSourceKind(raw)=="gcp-service-account-adc")!=(universe==""||universe=="googleapis.com"){t.Fatal("service account universe admission differs")}
 }
 nativeProcessState.policy.ExpectedSourceKind="gcp-service-account-adc"
 if nativeProcessObserveADC(serviceAccount)!=nil{t.Fatal("selected service account source refused")}
 badEndpoint:=bytes.Replace(serviceAccount,[]byte("https://oauth2.googleapis.com/token"),[]byte("https://example.invalid/token"),1)
 for _,other:=range [][]byte{badEndpoint,nil,raw,impersonated}{if nativeProcessObserveADC(other)==nil{t.Fatal("different or nonofficial ADC met service account requirement")}}
 for _,host:=range []string{"s3.us-east-1.amazonaws.com","kms.us-east-1.amazonaws.com","storage.us-central1.rep.googleapis.com","us-central1-cloudkms.googleapis.com"}{r,_:=http.NewRequest("GET","https://"+host+"/",nil);if !nativeProcessOfficialService(r){t.Fatal("installed service host refused",host)}}
 for _,url:=range []string{"http://kms.us-east-1.amazonaws.com/","https://kms.us-east-1.amazonaws.com:443/","https://user@kms.us-east-1.amazonaws.com/","https://kms.us-east-1.amazonaws.com.example/","https://storage.us-central1.rep.googleapis.com.example/","https://storage.us.central1.rep.googleapis.com/","https://example.com/"}{r,_:=http.NewRequest("GET",url,nil);if nativeProcessOfficialService(r){t.Fatal("noninstalled endpoint accepted")}}
 nativeProcessFinish(0)
 p,err:=nativeProcessLoad();if err!=nil{t.Fatal(err)};body,err:=os.ReadFile(p.RecordPath);if err!=nil||strings.Contains(string(body),"do-not-record")||strings.Contains(string(body),"private source detail"){t.Fatal("source observation exposed source contents")}
}
`

// full_only: false
func TestNativeCaptureSourceKindIsClosed(t *testing.T) {
	for _, source := range []string{"aws-sso", "aws-assume-role", "aws-shared-credentials", "gcp-user-adc", "gcp-impersonated-adc", "gcp-service-account-adc", "service-account-detail"} {
		for _, count := range []uint32{0, 1, 2} {
			body, err := json.Marshal(Event{Kind: "source-kind", SourceKind: source, Count: count, Matched: true})
			if err != nil {
				t.Fatal(err)
			}
			body = append(body, []byte("\n{\"kind\":\"footer\"}\n")...)
			path := filepath.Join(t.TempDir(), "capture")
			if err := os.WriteFile(path, body, 0600); err != nil {
				t.Fatal(err)
			}
			_, err = ReadCapture(path)
			if (err == nil) != (source != "service-account-detail" && count == 1) {
				t.Fatal("source capture enumeration or count admitted incorrectly", err)
			}
		}
	}
}

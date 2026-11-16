package nativeprocess

import (
	"context"
	"encoding/json"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// full_only: false
func TestNativeOverlayPreservesSourcesAndRefusesChangedAnchors(t *testing.T) {
	root, fixtures := nativeOverlayFixture(t, "package credentials\nfunc f(){return installed.Credentials, nil}")
	overlay, err := BuildOverlay(root, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var mapping struct{ Replace map[string]string }
	body, err := os.ReadFile(overlay.Path)
	if err != nil || json.Unmarshal(body, &mapping) != nil || len(mapping.Replace) != 34 {
		t.Fatal("native source closure differs", err)
	}
	for target, replacement := range mapping.Replace {
		body, err := os.ReadFile(replacement)
		if err != nil {
			t.Fatal(err)
		}
		switch filepath.Ext(target) {
		case ".go":
			if _, err := parser.ParseFile(token.NewFileSet(), replacement, body, parser.AllErrors); err != nil {
				t.Fatal("generated observation source is invalid", err)
			}
		case ".json":
			if !json.Valid(body) {
				t.Fatal("captured output descriptor is invalid JSON")
			}
		default:
			t.Fatal("overlay source extension has no format check")
		}
		if strings.HasSuffix(target, "nativeprocess_observer.go") || strings.HasSuffix(target, "nativeprocess_recovery.go") {
			if _, err := os.Stat(target); !os.IsNotExist(err) {
				t.Fatal("observer was written into production tree")
			}
		}
	}
	for _, provider := range []string{"aws", "gcp"} {
		leaf := filepath.Join(root, "providers", provider, "credentials")
		observer, err := os.ReadFile(mapping.Replace[filepath.Join(leaf, "nativeprocess_observer.go")])
		if err != nil || strings.Count(string(observer), sourceKindSource) != 1 {
			t.Fatal("credential source observer does not belong to its leaf", provider, err)
		}
		serviceObserver, err := os.ReadFile(mapping.Replace[filepath.Join(root, "providers", provider, "nativeprocess_observer.go")])
		if err != nil || strings.Contains(string(serviceObserver), sourceKindSource) {
			t.Fatal("service observer retained credential source classifiers", provider, err)
		}
		if mapping.Replace[filepath.Join(leaf, "credentials_default.go")] == "" || mapping.Replace[filepath.Join(root, "providers", provider, "credentials_default.go")] != "" {
			t.Fatal("credential loader observer does not belong to its leaf", provider)
		}
	}
	for _, plugin := range []struct{ name, pkg string }{{"aws-secrets-manager", "awssm"}, {"gcp-secret-manager", "gcpsm"}} {
		leaf := filepath.Join(filepath.Dir(root), "enkv-extensions", "plugins", "outputs", plugin.name, "internal", plugin.pkg)
		observer, err := os.ReadFile(mapping.Replace[filepath.Join(leaf, "nativeprocess_observer.go")])
		if err != nil || strings.Count(string(observer), sourceKindSource) != 1 || mapping.Replace[filepath.Join(leaf, "discovery.go")] == "" {
			t.Fatal("output credential observer does not belong to its actual SDK owner", plugin.name)
		}
	}
	for name, want := range fixtures {
		body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil || string(body) != want {
			t.Fatal("overlay changed installed source", name, err)
		}
	}
	path := filepath.Join(root, "providers/aws/transport.go")
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("package aws"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildOverlay(root, t.TempDir()); err == nil {
		t.Fatal("changed source anchor was silently accepted")
	}
}

// full_only: false
func TestNativeOverlayUsesBoundedDistinctReplacementNames(t *testing.T) {
	root, _ := nativeOverlayFixture(t, "package credentials\nfunc f(){return installed.Credentials, nil}")
	container := filepath.Join(t.TempDir(), strings.Repeat("long-workspace-", 10), strings.Repeat("nested-source-", 10))
	if err := os.MkdirAll(filepath.Dir(container), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Dir(root), container); err != nil {
		t.Fatal(err)
	}
	root = filepath.Join(container, filepath.Base(root))
	overlay, err := BuildOverlay(root, t.TempDir())
	if err != nil {
		t.Fatal("long source path could not construct its overlay", err)
	}
	var mapping struct{ Replace map[string]string }
	body, err := os.ReadFile(overlay.Path)
	if err != nil || json.Unmarshal(body, &mapping) != nil {
		t.Fatal("long source overlay unavailable")
	}
	seen := map[string]bool{}
	for target, replacement := range mapping.Replace {
		if len(filepath.Base(replacement)) > 80 || filepath.Ext(replacement) != filepath.Ext(target) || seen[replacement] {
			t.Fatal("overlay replacement name is unbounded, colliding or lost its extension")
		}
		seen[replacement] = true
	}
}

func nativeOverlayFixture(t *testing.T, credentials string) (string, map[string]string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "enkv-core")
	fixtures := map[string]string{
		"compositions/full/manifest_file.go":          "package compositionfull\nfunc (t *manifestFileTarget) install(ctx context.Context, artifact []byte, call *telemetry.Call) (facts ManifestDelivery) {\n r := manifestFileRun{}\n\tif !r.preflight() {\n return r.facts\n }\n return r.facts\n}\n",
		"compositions/aws/materialization.go":         "package compositionaws\nfunc f(){route, err := provider.NewKeyAccess(x)}",
		"compositions/gcp/materialization.go":         "package compositiongcp\nfunc f(){route, err := provider.NewKeyAccess(x)}",
		"compositions/configuration/write.go":         "package configuration\nfunc nativeEditIO() editIO { return editIO{remove: os.Remove, phase: func(string) error { return nil }, freeBytes: availableEditBytes,} }\nfunc (s *EditSession) unknown(c *EditCandidate, cause error) *UnknownEdit {\nreturn nil\n}\nfunc (o *EditObservation) Close() error {\nreturn nil\n}\n",
		"compositions/full/configuration_keys_aws.go": "package compositionfull\nfunc f(){\nanchor, err := awsprovider.NewPublicSigningAnchor(x)\npublic, fingerprint, protection, result := awsprovider.ResolveEncryptionKey(x)\nreturn awsprovider.NewTrust(x)\nreturn awsprovider.NewKeyAccess(x)\nreturn awsprovider.NewPublicEncryptionQualifier(x)\n}\n",
		"compositions/full/configuration_keys_gcp.go": "package compositionfull\nfunc f(){\nanchor, err := gcpprovider.NewPublicSigningAnchor(x)\npublic, fingerprint, protection, result := gcpprovider.ResolveEncryptionKey(x)\nreturn gcpprovider.NewTrust(x)\nreturn gcpprovider.NewKeyAccess(x)\nreturn gcpprovider.NewPublicEncryptionQualifier(x)\n}\n",
		"providers/aws/transport.go":                  "package aws\nfunc f(){r.GetBody = nil\nresp, err := t.next.RoundTrip(r)}",
		"providers/gcp/transport.go":                  "package gcp\nfunc f(){private := httptransport.PrivateContext(ctx)\nresponse, err := s.base.RoundTrip(frozen)}",
		"providers/aws/store.go": `package awsprovider
func (s *Store) write(ctx context.Context, key string, token contract.Token, body []byte, cas bool) contract.WriteResult { return contract.WriteResult{} }
func (s *Store) DeleteIfToken(ctx context.Context, key string, token contract.Token) (result contract.WriteResult) {
	if s == nil ||
		keyLimit(s.config.Prefix, s.config.Domain, key) == 0 || token.Family != contract.AWS || !token.Valid() {
		return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonConstruction}
	}
	return contract.WriteResult{}
}
`,
		"providers/gcp/store.go": `package gcp
func (s *Store) write(ctx context.Context, key string, generation int64, body []byte) contract.WriteResult { return contract.WriteResult{} }
func (s *Store) DeleteIfToken(ctx context.Context, key string, token contract.Token) (result contract.WriteResult) {
	generation, err := strconv.ParseInt(token.Value, 10, 64)
	if err != nil || generation <= 0 || strconv.FormatInt(generation, 10) != token.Value {
		return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonConstruction}
	}
	ctx, ok := s.config.Client.begin(ctx, s.host, maxJSON)
	return contract.WriteResult{}
}
`,
		"providers/aws/credentials/credentials_default.go":                                                       credentials,
		"providers/gcp/credentials/credentials_default.go":                                                       "package credentials\nfunc f(){universe, err := selected.UniverseDomain(ctx)}",
		"crypto/reconstruction_verifier.go":                                                                      "package crypto\nfunc f(){\nplain, _, code := openConsumerValue(ctx, a, route, selected, index, packetContext)\n\treturn sessionCancellation(ctx, a)\n}\n\nfunc reconstructionSelectionMatches(){}",
		"compositions/full/cmd/enkv/apply.go":                                                                    "package main\nfunc f(){ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)}",
		"compositions/full/cmd/enkv/secret_access.go":                                                            "package main\nfunc runEnvelopeRekey(args []string, out, diagnostic io.Writer) int {\n\tctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)\n\tdefer cancel()\n\treturn 0\n}\nfunc runRecipientRetirement(args []string, out, diagnostic io.Writer) int {\n\tctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)\n\tdefer cancel()\n\treturn 0\n}\n",
		"compositions/full/cmd/enkv/main.go":                                                                     "package main\nfunc main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }",
		"../enkv-extensions/plugins/outputs/aws-secrets-manager/cmd/enkv-output-aws-secrets-manager/plugin.json": `{"name":"aws-secrets-manager"}`,
		"../enkv-extensions/plugins/outputs/gcp-secret-manager/cmd/enkv-output-gcp-secret-manager/plugin.json":   `{"name":"gcp-secret-manager"}`,
		"../enkv-extensions/plugins/outputs/aws-secrets-manager/internal/awssm/discovery.go":                     "package awssm\nfunc f(){return installed.Credentials, nil}\nfunc g(){expiry := time.Time{}}",
		"../enkv-extensions/plugins/outputs/gcp-secret-manager/internal/gcpsm/discovery.go":                      "package gcpsm\nfunc f(){selected, err := authcredentials.DetectDefault(options{Client: &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},}); return credentialSource{selected, quota}, nil}",
	}
	for name, body := range fixtures {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0444); err != nil {
			t.Fatal(err)
		}
	}
	return root, fixtures
}

// full_only: false
func TestNativeCaptureRequiresJoinedNormalReturn(t *testing.T) {
	valid := []Event{{Kind: "http-start", Operation: "head-read", Sequence: 1, Sent: true}, {Kind: "http-return", Operation: "head-read", Sequence: 1, Sent: true, Status: 200}, {Kind: "plaintext", Count: 1, Matched: true, EntrySHA256: strings.Repeat("a", 64)}, {Kind: "footer"}}
	for _, condition := range []string{"complete", "missing-return", "missing-footer", "duplicate-sequence", "after-footer", "unknown-field"} {
		t.Run(condition, func(t *testing.T) {
			events := append([]Event(nil), valid...)
			switch condition {
			case "missing-return":
				events = append(events[:1], events[2:]...)
			case "missing-footer":
				events = events[:len(events)-1]
			case "duplicate-sequence":
				events = append(append(events[:2:2], events[:2]...), events[2:]...)
			case "after-footer":
				events = append(events, Event{Kind: "plaintext"})
			}
			var encoded strings.Builder
			for _, event := range events {
				body, err := json.Marshal(event)
				if err != nil {
					t.Fatal(err)
				}
				encoded.Write(body)
				encoded.WriteByte('\n')
			}
			if condition == "unknown-field" {
				encoded.Reset()
				encoded.WriteString("{\"kind\":\"footer\",\"token\":\"forbidden\"}\n")
			}
			path := filepath.Join(t.TempDir(), "capture")
			if err := os.WriteFile(path, []byte(encoded.String()), 0600); err != nil {
				t.Fatal(err)
			}
			_, err := ReadCapture(path)
			if (err == nil) != (condition == "complete") {
				t.Fatal("capture completeness differs", err)
			}
		})
	}
}

// full_only: false
func TestNativeCaptureBoundsLocalEditObservations(t *testing.T) {
	for _, kind := range []string{"local-edit-fault", "local-edit-unknown", "local-edit-disposed"} {
		valid := Event{Kind: kind, Count: 1}
		if kind == "local-edit-disposed" {
			valid.Count, valid.Matched = 4, true
		}
		for _, condition := range []string{"valid", "count", "path", "role"} {
			t.Run(kind+"/"+condition, func(t *testing.T) {
				event := valid
				switch condition {
				case "count":
					event.Count++
				case "path":
					event.ObjectKeySHA256 = strings.Repeat("a", 64)
				case "role":
					event.Role = "authority"
				}
				var body strings.Builder
				encoder := json.NewEncoder(&body)
				if encoder.Encode(event) != nil || encoder.Encode(Event{Kind: "footer"}) != nil {
					t.Fatal("local edit observation fixture unavailable")
				}
				_, err := inspectCaptureImage([]byte(body.String()), true)
				if (err == nil) != (condition == "valid") {
					t.Fatal("local edit observation field bound differs", err)
				}
			})
		}
	}
}

func nativeCredentialObserverBinary(t *testing.T) string {
	t.Helper()
	root, _ := nativeOverlayFixture(t, `package credentials
import("context";"github.com/aws/aws-sdk-go-v2/aws")
func selectedCredentials(ctx context.Context, installed aws.Config) (aws.CredentialsProvider, error) {
 return installed.Credentials, nil
}
`)
	dir := t.TempDir()
	overlay, err := BuildOverlay(root, dir)
	if err != nil {
		t.Fatal(err)
	}
	var mapping struct{ Replace map[string]string }
	body, err := os.ReadFile(overlay.Path)
	if err != nil || json.Unmarshal(body, &mapping) != nil {
		t.Fatal("read generated endpoint observer", err)
	}
	testPath := filepath.Join(dir, "endpoint_test.go")
	if err := os.WriteFile(testPath, []byte(nativeEndpointTest), 0600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "endpoint.test")
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	build := exec.CommandContext(ctx, "go", nativeGoArguments("test", "-c", "-mod=readonly", "-o", binary,
		mapping.Replace[filepath.Join(root, "providers/aws/credentials/credentials_default.go")],
		mapping.Replace[filepath.Join(root, "providers/aws/credentials/nativeprocess_observer.go")], testPath)...)
	build.Dir = filepath.Join(nativeRepository(t), "providers", "aws")
	build.Env = append(os.Environ(), "GOPROXY=off", "GOSUMDB=off")
	prepareNativeModule(t, nativeRepository(t), build, binary+".mod")
	if body, err := build.CombinedOutput(); err != nil {
		t.Fatalf("generated credential endpoint observer did not build: %v\n%s", err, body)
	}
	return binary
}

// full_only: false
func TestNativeOverlayRejectsCredentialEndpointOverridesBeforeRetrieval(t *testing.T) {
	binary := nativeCredentialObserverBinary(t)
	for _, condition := range []string{"base", "configured-sso", "configured-oidc", "configured-sts", "error-sso", "error-oidc", "error-sts", "default", "empty"} {
		t.Run(condition, func(t *testing.T) {
			dir := t.TempDir()
			record := filepath.Join(dir, "capture")
			policyPath := filepath.Join(dir, "policy.json")
			body, err := json.Marshal(Policy{Version: 1, RecordPath: record, MaxRequests: 1, MaxBytes: 1024, RequireStandardSource: true, ExpectedSourceKind: "aws-assume-role"})
			if err != nil {
				t.Fatal(err)
			}
			for path, body := range map[string][]byte{record: nil, policyPath: body} {
				if err := os.WriteFile(path, body, 0600); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			child := exec.CommandContext(ctx, binary, "-test.run=^TestEndpointGate$", "-test.v")
			child.Env = append(os.Environ(), "ENKV_NATIVE_PROCESS_POLICY="+policyPath, "ENKV_ENDPOINT_CASE="+condition)
			body, err = child.CombinedOutput()
			if err != nil || !strings.Contains(string(body), "=== RUN   TestEndpointGate\n") || !strings.Contains(string(body), "--- PASS: TestEndpointGate (") {
				t.Fatalf("generated endpoint gate did not complete its selected test: %v\n%s", err, body)
			}
		})
	}
}

const nativeEndpointTest = `package credentials
import("context";"errors";"os";"reflect";"strings";"testing";"github.com/aws/aws-sdk-go-v2/aws")
type endpointConfiguration struct { condition, service string; queries []string }
func (c *endpointConfiguration) GetServiceBaseEndpoint(_ context.Context, service string) (string,bool,error) {
 c.queries=append(c.queries,service)
 if c.condition=="empty" {return "",true,nil}
 if service!=c.service { return "",false,nil }
 if strings.HasPrefix(c.condition,"error-") { return "",false,errors.New("lookup failed") }
 return "https://override.invalid",true,nil
}
type countedCredentials struct { calls int }
func(c *countedCredentials) Retrieve(context.Context)(aws.Credentials,error) { c.calls++;return aws.Credentials{Source:"AssumeRoleProvider"},nil }
// full_only: false
func TestEndpointGate(t *testing.T) {
 condition:=os.Getenv("ENKV_ENDPOINT_CASE")
 configured:=&endpointConfiguration{condition:condition}
 services:=[]string{"SSO","SSO OIDC","STS"}
 wantQueries:=services
 for i,suffix:=range []string{"sso","oidc","sts"} { if strings.HasSuffix(condition,"-"+suffix) {configured.service=services[i];wantQueries=services[:i+1]} }
 source:=&countedCredentials{}
 installed:=aws.Config{Credentials:source,ConfigSources:[]any{struct{}{},configured}}
 wantRefused:=condition!="default"&&condition!="empty"
 if condition=="base" { endpoint:="https://override.invalid";installed.BaseEndpoint=&endpoint;wantQueries=nil }
 if condition=="empty" { endpoint:="";installed.BaseEndpoint=&endpoint }
 selected,err:=selectedCredentials(t.Context(),installed)
 if wantRefused {
  if !errors.Is(err,nativeProcessRefused)||selected!=nil {t.Fatal("configured credential endpoint did not refuse at loader boundary",err)}
 } else {
  if err!=nil||selected==nil {t.Fatal("default credential route refused",err)}
  if _,err:=selected.Retrieve(t.Context());err!=nil {t.Fatal("default credential retrieval refused",err)}
 }
 wantCalls:=0;if !wantRefused {wantCalls=1}
 if source.calls!=wantCalls {t.Fatal("credential retrieval crossed endpoint refusal",source.calls,wantCalls)}
 if !reflect.DeepEqual(configured.queries,wantQueries) {t.Fatal("credential endpoint lookup order differs",configured.queries,wantQueries)}
}

type fixedSourceCredentials struct { value aws.Credentials; calls int }
func(c *fixedSourceCredentials) Retrieve(context.Context)(aws.Credentials,error){c.calls++;return c.value,nil}
// full_only: false
func TestSharedSourceGate(t *testing.T){
 condition:=os.Getenv("ENKV_SHARED_CASE")
 value:=aws.Credentials{Source:"SharedConfigCredentials: /private-selected-file",AccessKeyID:"synthetic-key",SecretAccessKey:"synthetic-secret"}
 switch condition {
 case "session-token": value.SessionToken="synthetic-session"
 case "expiring": value.CanExpire=true
 case "sso": value.Source="SSOProvider"
 case "assume-role": value.Source="AssumeRoleProvider"
 case "environment": value.Source="EnvConfigCredentials"
 case "process": value.Source="ProcessProvider"
 case "metadata": value.Source="EC2RoleProvider"
 case "missing-file": value.Source="SharedConfigCredentials:"
 }
 source:=&fixedSourceCredentials{value:value}
 selected,err:=selectedCredentials(t.Context(),aws.Config{Credentials:source})
 if err!=nil||selected==nil{t.Fatal("source could not reach selected retrieval gate",err)}
 got,err:=selected.Retrieve(t.Context())
 if condition=="shared" {if err!=nil||got!=value{t.Fatal("direct shared credentials refused",err)}} else if !errors.Is(err,nativeProcessRefused)||got!=(aws.Credentials{}){t.Fatal("wrong credential source returned before resource use",err)}
 if source.calls!=1{t.Fatal("unexpected source retrieval count")}
 nativeProcessFinish(0)
}
`

// full_only: false
func TestNativeSharedCredentialsRequireDirectNonexpiringSource(t *testing.T) {
	binary := nativeCredentialObserverBinary(t)
	for _, condition := range []string{"shared", "session-token", "expiring", "sso", "assume-role", "environment", "process", "metadata", "missing-file"} {
		t.Run(condition, func(t *testing.T) {
			dir := t.TempDir()
			record := filepath.Join(dir, "capture")
			policyPath := filepath.Join(dir, "policy.json")
			body, err := json.Marshal(Policy{Version: 1, RecordPath: record, MaxRequests: 1, MaxBytes: 1024, RequireStandardSource: true, ExpectedSourceKind: "aws-shared-credentials"})
			if err != nil {
				t.Fatal(err)
			}
			for path, body := range map[string][]byte{record: nil, policyPath: body} {
				if err := os.WriteFile(path, body, 0600); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			child := exec.CommandContext(ctx, binary, "-test.run=^TestSharedSourceGate$", "-test.v")
			child.Env = append(os.Environ(), "ENKV_NATIVE_PROCESS_POLICY="+policyPath, "ENKV_SHARED_CASE="+condition)
			body, err = child.CombinedOutput()
			if err != nil || !strings.Contains(string(body), "=== RUN   TestSharedSourceGate\n") || !strings.Contains(string(body), "--- PASS: TestSharedSourceGate (") {
				t.Fatalf("shared source gate did not complete: %v\n%s", err, body)
			}
			capture, err := ReadCapture(record)
			if err != nil || len(capture.Events) != 2 || capture.Events[0].Matched != (condition == "shared") {
				t.Fatal("shared source capture differs", err)
			}
			raw, err := os.ReadFile(record)
			if err != nil || strings.Contains(string(raw), "synthetic-secret") || strings.Contains(string(raw), "private-selected-file") {
				t.Fatal("shared source observation exposed credentials or file selector")
			}
		})
	}
}

// full_only: false
func TestGeneratedOverlayBindsEffectiveSourcesAndMaintainedLedger(t *testing.T) {
	root := nativeRepository(t)
	overlay, err := BuildOverlay(root, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	overlay, err = AddGeneratedLedgerOverlay(root, overlay)
	if err != nil {
		t.Fatal(err)
	}
	var mapping struct{ Replace map[string]string }
	var sources []Source
	body, err := os.ReadFile(overlay.Path)
	if err != nil || json.Unmarshal(body, &mapping) != nil || digest(body) != overlay.SHA256 {
		t.Fatal("generated overlay mapping identity differs", err)
	}
	body, err = os.ReadFile(overlay.Manifest)
	if err != nil || json.Unmarshal(body, &sources) != nil || digest(body) != overlay.ManifestSHA256 {
		t.Fatal("generated overlay effective source identity differs", err)
	}
	seen := map[string]bool{}
	for _, source := range sources {
		if seen[source.Target] || mapping.Replace[source.Target] != source.Replacement {
			t.Fatal("generated source mapping differs")
		}
		seen[source.Target] = true
		effective, err := os.ReadFile(source.Replacement)
		if err != nil || digest(effective) != source.ReplacementSHA256 {
			t.Fatal("effective generated overlay source is not bound", err)
		}
		switch filepath.Ext(source.Target) {
		case ".go":
			if _, err := parser.ParseFile(token.NewFileSet(), source.Target, effective, parser.AllErrors); err != nil {
				t.Fatal("effective generated source does not parse", err)
			}
		case ".json":
			if !json.Valid(effective) {
				t.Fatal("effective output descriptor is invalid JSON")
			}
		default:
			t.Fatal("generated overlay source extension has no format check")
		}
	}
	for _, name := range []string{"io.go", "generator_ledger.go"} {
		original, err := os.ReadFile(filepath.Join(root, "tests", "shared", "records", name))
		if err != nil {
			t.Fatal(err)
		}
		effective, err := os.ReadFile(mapping.Replace[filepath.Join(root, "compositions", "full", "nativeprocess_generated_"+name)])
		if err != nil || string(effective) != strings.Replace(string(original), "package records", "package compositionfull", 1) {
			t.Fatal("generated observer forked maintained ledger/durability behavior", name, err)
		}
	}
	if _, err := AddGeneratedLedgerOverlay(root, overlay); err == nil {
		t.Fatal("duplicate generated observer silently replaced effective source")
	}
}

// full_only: false
func TestGeneratedCaptureRequiresPairedExactNativeResult(t *testing.T) {
	entry := Event{Kind: "generator-entry", GeneratorAccount: strings.Repeat("a", 32), GeneratorAttempt: strings.Repeat("b", 64), GeneratorAction: 1}
	result := entry
	result.Kind, result.GeneratorQualified, result.GeneratorTarget = "generator-return", true, strings.Repeat("c", 32)
	for _, condition := range []string{"exact", "missing-entry", "missing-return", "account", "action", "field-owner", "qualified-entry", "invalid-target"} {
		t.Run(condition, func(t *testing.T) {
			events := []Event{entry, result, {Kind: "footer"}}
			switch condition {
			case "missing-entry":
				events = events[1:]
			case "missing-return":
				events = append(events[:1:1], events[2:]...)
			case "account":
				events[1].GeneratorAccount = strings.Repeat("d", 32)
			case "action":
				events[1].GeneratorAction = 2
			case "field-owner":
				events[2].GeneratorAccount = entry.GeneratorAccount
			case "qualified-entry":
				events[0].GeneratorQualified = true
			case "invalid-target":
				events[1].GeneratorTarget = ""
			}
			var body []byte
			for _, event := range events {
				encoded, err := json.Marshal(event)
				if err != nil {
					t.Fatal(err)
				}
				body = append(append(body, encoded...), '\n')
			}
			_, err := InspectCapture(body)
			if (err == nil) != (condition == "exact") {
				t.Fatal("native generated capture lost entry/result binding", condition, err)
			}
		})
	}
	// Fixed wire values exercise admission independently of the event encoder.
	for _, tc := range []struct {
		name, observation string
		qualified, valid  bool
	}{
		{"qualified", `{"code":1,"common_facts":{"disposition":1,"reason":0},"expected_result_valid":true,"qualification":"qualified"}`, true, true},
		{"unknown-facts", `{"code":1,"common_facts":{"disposition":5,"reason":5},"expected_result_valid":false,"qualification":"facts-refused"}`, false, true},
		{"invalid-facts", `{"code":1,"expected_result_valid":false,"qualification":"facts-refused"}`, false, true},
		{"producer-failed", `{"code":12,"expected_result_valid":false,"qualification":"producer-failed"}`, false, true},
		{"resource-unavailable", `{"code":1,"common_facts":{"disposition":1,"reason":0},"expected_result_valid":true,"qualification":"resource-unavailable"}`, false, true},
		{"disposition-refused", `{"code":1,"common_facts":{"disposition":6,"reason":0},"expected_result_valid":true,"qualification":"disposition-refused"}`, false, true},
		{"ledger-unavailable", `{"code":1,"common_facts":{"disposition":1,"reason":0},"expected_result_valid":true,"qualification":"ledger-unavailable"}`, false, true},
		{"null", `null`, false, false},
		{"missing-code", `{"expected_result_valid":false,"qualification":"producer-failed"}`, false, false},
		{"invalid-code", `{"code":13,"expected_result_valid":false,"qualification":"producer-failed"}`, false, false},
		{"folded-code", `{"CODE":1,"expected_result_valid":false,"qualification":"facts-refused"}`, false, false},
		{"missing-expected", `{"code":1,"qualification":"facts-refused"}`, false, false},
		{"null-expected", `{"code":1,"expected_result_valid":null,"qualification":"facts-refused"}`, false, false},
		{"foreign-field", `{"code":1,"expected_result_valid":false,"qualification":"facts-refused","raw_error":"forbidden"}`, false, false},
		{"null-common-facts", `{"code":1,"common_facts":null,"expected_result_valid":false,"qualification":"facts-refused"}`, false, false},
		{"missing-reason", `{"code":1,"common_facts":{"disposition":5},"expected_result_valid":false,"qualification":"facts-refused"}`, false, false},
		{"null-reason", `{"code":1,"common_facts":{"disposition":5,"reason":null},"expected_result_valid":false,"qualification":"facts-refused"}`, false, false},
		{"invalid-disposition", `{"code":1,"common_facts":{"disposition":9,"reason":0},"expected_result_valid":false,"qualification":"facts-refused"}`, false, false},
		{"invalid-reason", `{"code":1,"common_facts":{"disposition":5,"reason":11},"expected_result_valid":false,"qualification":"facts-refused"}`, false, false},
		{"foreign-common-field", `{"code":1,"common_facts":{"disposition":5,"reason":5,"provider_facts":"forbidden"},"expected_result_valid":false,"qualification":"facts-refused"}`, false, false},
		{"unknown-stage", `{"code":1,"expected_result_valid":false,"qualification":"other"}`, false, false},
		{"failed-producer-stage", `{"code":2,"expected_result_valid":false,"qualification":"facts-refused"}`, false, false},
		{"invalid-expected-stage", `{"code":1,"expected_result_valid":false,"qualification":"qualified"}`, true, false},
		{"missing-common-facts", `{"code":1,"expected_result_valid":true,"qualification":"qualified"}`, true, false},
		{"qualification-mismatch", `{"code":1,"common_facts":{"disposition":1,"reason":0},"expected_result_valid":true,"qualification":"qualified"}`, false, false},
		{"wrong-disposition", `{"code":1,"common_facts":{"disposition":4,"reason":0},"expected_result_valid":true,"qualification":"qualified"}`, true, false},
		{"complete-with-reason", `{"code":1,"common_facts":{"disposition":1,"reason":7},"expected_result_valid":true,"qualification":"qualified"}`, true, false},
		{"unknown-without-reason", `{"code":1,"common_facts":{"disposition":5,"reason":0},"expected_result_valid":false,"qualification":"facts-refused"}`, false, false},
		{"unusable-without-reason", `{"code":1,"common_facts":{"disposition":2,"reason":0},"expected_result_valid":true,"qualification":"qualified"}`, true, false},
		{"create-disposition-stage", `{"code":1,"common_facts":{"disposition":1,"reason":0},"expected_result_valid":true,"qualification":"disposition-refused"}`, false, false},
		{"create-resource-stage", `{"code":1,"common_facts":{"disposition":1,"reason":0},"expected_result_valid":true,"qualification":"resource-unavailable"}`, false, false},
		{"delete-resource-stage", `{"code":1,"common_facts":{"disposition":4,"reason":0},"expected_result_valid":true,"qualification":"resource-unavailable"}`, false, false},
		{"delete-disposition-stage", `{"code":1,"common_facts":{"disposition":4,"reason":0},"expected_result_valid":true,"qualification":"disposition-refused"}`, false, false},
	} {
		t.Run("return/"+tc.name, func(t *testing.T) {
			entered := entry
			observed := result
			observed.GeneratorQualified = tc.qualified
			if tc.name == "resource-unavailable" {
				observed.GeneratorTarget = ""
			}
			if tc.name == "disposition-refused" || strings.HasPrefix(tc.name, "delete-") {
				entered.GeneratorAction, observed.GeneratorAction = 2, 2
				entered.GeneratorTarget = observed.GeneratorTarget
			}
			start, err := json.Marshal(entered)
			if err != nil {
				t.Fatal(err)
			}
			end, err := json.Marshal(observed)
			if err != nil {
				t.Fatal(err)
			}
			end = append(end[:len(end)-1], []byte(`,"generator_return":`+tc.observation+`}`)...)
			body := append(append(append(start, '\n'), end...), []byte("\n{\"kind\":\"footer\"}\n")...)
			_, err = InspectCapture(body)
			if (err == nil) != tc.valid {
				t.Fatal("producer observation admission differs", err)
			}
			if !tc.valid {
				return
			}
			for _, field := range []string{"Generator_Return", "GENERATOR_RETURN"} {
				if _, err := InspectCapture([]byte(strings.ReplaceAll(string(body), "generator_return", field))); err == nil {
					t.Fatal("folded observation field accepted")
				}
			}
			foreign := append(start[:len(start)-1:len(start)-1], []byte(`,"generator_return":`+tc.observation+"}\n")...)
			foreign = append(foreign, body[len(start)+1:]...)
			if _, err := InspectCapture(foreign); err == nil {
				t.Fatal("entry accepted return observation")
			}
		})
	}
}

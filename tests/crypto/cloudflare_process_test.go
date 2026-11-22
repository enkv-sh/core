package crypto

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"enkv.sh/compositions/generatorhost"
	"enkv.sh/core/contract"
	"enkv.sh/sdk/artifact"
	wire "enkv.sh/sdk/protocols/generator"
)

const (
	cloudflareSemanticOrigin = "https://api.cloudflare.com/client/v4"
	cloudflareAccount        = "0123456789abcdef0123456789abcdef"
	cloudflarePermission     = "11111111111111111111111111111111"
	cloudflareTokenID        = "22222222222222222222222222222222"
	cloudflareBearer         = "Management_bearer_0123456789_ABCDEFGHIJKLMN"
	cloudflareSecret         = "Generated_secret_0123456789_ABCDEFGHIJKLMN"
)

type cloudflareProcessScenario struct {
	status   int
	body     []byte
	earlyEOF bool
	method   string
	path     string
	request  []byte
}

type cloudflareProcessServer struct {
	t        *testing.T
	mu       sync.Mutex
	active   cloudflareProcessScenario
	requests atomic.Int32
}

func (s *cloudflareProcessServer) set(v cloudflareProcessScenario) int32 {
	s.mu.Lock()
	s.active = v
	s.mu.Unlock()
	return s.requests.Load()
}

func (s *cloudflareProcessServer) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	s.requests.Add(1)
	s.mu.Lock()
	scenario := s.active
	s.mu.Unlock()
	body, err := io.ReadAll(io.LimitReader(request.Body, 1<<20))
	if err != nil || request.Method != scenario.method || request.URL.Path != scenario.path || request.ProtoMajor != 1 || !request.Close ||
		request.Header.Get("Authorization") != "Bearer "+cloudflareBearer || request.Header.Get("Accept-Encoding") != "identity" ||
		!bytes.Equal(body, scenario.request) {
		s.t.Errorf("unexpected Cloudflare test request: method=%s path=%s proto=%s close=%t body=%q err=%v", request.Method, request.URL.Path, request.Proto, request.Close, body, err)
	}
	if scenario.earlyEOF {
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			s.t.Error("Cloudflare TLS server cannot inject early EOF")
			return
		}
		connection, buffer, err := hijacker.Hijack()
		if err != nil {
			s.t.Error(err)
			return
		}
		_, _ = buffer.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{}")
		_ = buffer.Flush()
		_ = connection.Close()
		return
	}
	status := scenario.status
	if status == 0 {
		status = http.StatusOK
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(scenario.body)
}

func cloudflareID(label string) contract.ID { return sha256.Sum256([]byte(label)) }

// These literals follow the official settings field order. The contract IDs
// bind the service origin; the tagged build changes only its test transport.
func cloudflareTestIntent() ([]byte, []byte) {
	settings := []byte(fmt.Sprintf(`{"account":"%s","name":"generated","policies":[{"effect":"allow","permission_groups":["%s"],"resources":[{"kind":"account","id":"%s"}]}]}`, cloudflareAccount, cloudflarePermission, cloudflareAccount))
	config := cloudflareID("ENKV/CLOUDFLARE-ACCOUNT-TOKEN/CONFIG/v1\x00" + cloudflareSemanticOrigin)
	resource := cloudflareID("ENKV/CLOUDFLARE-ACCOUNT-TOKEN/RESOURCE/v1\x00" + cloudflareSemanticOrigin)
	intent := binary.BigEndian.AppendUint16(nil, 1)
	intent = append(intent, config[:]...)
	intent = append(intent, 2)
	intent = append(intent, resource[:]...)
	intent = binary.BigEndian.AppendUint32(intent, uint32(len(settings)))
	intent = append(intent, settings...)
	request := []byte(fmt.Sprintf(`{"name":"generated","policies":[{"effect":"allow","permission_groups":[{"id":"%s"}],"resources":{"com.cloudflare.api.account.%s":"*"}}]}`, cloudflarePermission, cloudflareAccount))
	return intent, request
}

func cloudflareDigest(label string, body []byte) contract.ID {
	preimage := append([]byte("ENKV/GENERATOR/v1/"+label+"\x00"), binary.BigEndian.AppendUint32(nil, uint32(len(body)))...)
	preimage = append(preimage, body...)
	return sha256.Sum256(preimage)
}

func cloudflareRequestDigest(action uint8, intent, target []byte) contract.ID {
	preimage := append([]byte("ENKV/GENERATOR-REQUEST/v1\x00"), action)
	for _, body := range [][]byte{intent, target} {
		preimage = binary.BigEndian.AppendUint32(preimage, uint32(len(body)))
		preimage = append(preimage, body...)
	}
	return sha256.Sum256(preimage)
}

func buildCloudflareTestProcess(t *testing.T, origin string) (string, *generatorhost.Installation) {
	t.Helper()
	directory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	plugin := filepath.Clean(filepath.Join(directory, "../../enkv-extensions/plugins/generators/cloudflare-account-token"))
	path := filepath.Join(t.TempDir(), "enkv-generator-cloudflare-test")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-tags=enkv_cloudflare_testartifact",
		"-ldflags=-X=enkv.sh/plugins/generators/cloudflare-account-token/internal/cloudflare.unqualifiedTestArtifactOrigin="+origin,
		"-o", path, "./cmd/enkv-generator-cloudflare-test")
	command.Dir = plugin
	command.Env = append(os.Environ(), "GOWORK=off", "GOTOOLCHAIN=local", "GOFLAGS=-trimpath")
	prepareNativeModule(t, filepath.Dir(directory), command, path+".mod")
	descriptor, _, err := artifact.ReadDescriptor(t.Context(), filepath.Join(plugin, "cmd/enkv-generator-cloudflare-test/plugin.json"))
	if err != nil {
		t.Fatal(err)
	}
	modules, packages, sources := cloudflareBuildInputs(t, command)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build tagged Cloudflare process: %v\n%s", err, output)
	}
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	metadata, dependency := cloudflareBuildMetadata(t, path, command, descriptor, modules, packages, sources)
	installed, err := generatorhost.NewInstallation(metadata, dependency)
	if err != nil || installed.Artifact().NativeTuple != runtime.GOOS+"/"+runtime.GOARCH {
		t.Fatal("bind tagged Cloudflare process", err)
	}
	return path, installed
}

func cloudflareProcessLauncher(t *testing.T, path string, installed *generatorhost.Installation) *generatorhost.NativeLauncher {
	t.Helper()
	launcher, err := generatorhost.NewNative(t.Context(), generatorhost.Config{Installation: installed, ArtifactPath: path, Artifact: installed.Artifact()})
	if err != nil {
		t.Fatal("admit tagged Cloudflare process", err)
	}
	return launcher
}

func cloudflareProcessCommand(implementation contract.GeneratorImplementation, intent []byte) contract.GeneratedProducerCommand {
	return contract.GeneratedProducerCommand{
		GeneratedProducerPreparation: contract.GeneratedProducerPreparation{Schema: contract.GeneratedProducerCommandSchema,
			DomainID: cloudflareID("domain"), OperationID: cloudflareID("operation"), RequestIdentityDigest: cloudflareID("request"),
			PlanGraphID: cloudflareID("graph"), LineageID: cloudflareID("lineage"), AttemptID: cloudflareID("attempt"),
			TransmissionID: cloudflareID("transmission"), ResultID: cloudflareID("result"), ResultContractID: cloudflareID("result contract"),
			DescriptorID: implementation.DescriptorID, ExecutorID: implementation.ExecutorID, CredentialRouteID: implementation.CredentialRouteID,
			Action: 1, LifecycleMode: contract.GeneratorLifecycleManaged,
			ResourceContractID: cloudflareID("ENKV/CLOUDFLARE-ACCOUNT-TOKEN/RESOURCE/v1\x00" + cloudflareSemanticOrigin),
			RequestDigest:      cloudflareRequestDigest(1, intent, nil), IntentDigest: cloudflareDigest("intent-v3", intent),
		},
		DeadlineUnixMillis: uint64(time.Now().Add(10 * time.Second).UnixMilli()), Intent: bytes.Clone(intent),
	}
}

type changedCloudflareRequestLauncher struct{ generatorhost.Launcher }

func (l changedCloudflareRequestLauncher) Start(ctx context.Context, command wire.Command, result *os.File) (generatorhost.Run, error) {
	command.RequestDigest[0] ^= 1
	return l.Launcher.Start(ctx, command, result)
}

func cloudflareCreateResponse(value, status, name string, includeValue bool) []byte {
	valueField := ""
	if includeValue {
		valueField = fmt.Sprintf(`,"value":"%s"`, value)
	}
	return []byte(fmt.Sprintf(`{"success":true,"errors":[],"messages":[],"result":{"id":"%s"%s,"status":"%s","name":"%s","policies":[{"effect":"allow","permission_groups":[{"id":"%s"}],"resources":{"com.cloudflare.api.account.%s":"*"}}]}}`,
		cloudflareTokenID, valueField, status, name, cloudflarePermission, cloudflareAccount))
}

// full_only: false
func TestCloudflareTaggedProcessCrossesHostAndCryptoOnce(t *testing.T) {
	serverState := &cloudflareProcessServer{t: t}
	server := httptest.NewUnstartedServer(serverState)
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	origin := server.URL + "/client/v4"
	path, installed := buildCloudflareTestProcess(t, origin)
	implementation := installed.Artifact()
	t.Setenv("CLOUDFLARE_API_TOKEN", cloudflareBearer)
	intent, requestBody := cloudflareTestIntent()
	createPath := "/client/v4/accounts/" + cloudflareAccount + "/tokens"
	rejected := []byte(`{"success":false,"errors":[{"code":9109,"message":"denied"}],"messages":[],"result":null}`)
	complete := cloudflareCreateResponse(cloudflareSecret, "active", "generated", true)
	cases := []struct {
		name        string
		scenario    cloudflareProcessScenario
		disposition uint8
		reason      uint8
		secret      string
	}{
		{name: "qualified create", scenario: cloudflareProcessScenario{body: complete}, disposition: 1, secret: cloudflareSecret},
		{name: "missing value", scenario: cloudflareProcessScenario{body: cloudflareCreateResponse("", "active", "generated", false)}, disposition: 2, reason: 1},
		{name: "invalid value", scenario: cloudflareProcessScenario{body: cloudflareCreateResponse("short", "active", "generated", true)}, disposition: 2, reason: 2},
		{name: "changed controls", scenario: cloudflareProcessScenario{body: cloudflareCreateResponse(cloudflareSecret, "active", "other", true)}, disposition: 2, reason: 3},
		{name: "inactive", scenario: cloudflareProcessScenario{body: cloudflareCreateResponse(cloudflareSecret, "disabled", "generated", true)}, disposition: 2, reason: 4},
		{name: "malformed", scenario: cloudflareProcessScenario{body: []byte(`{"success":`)}, disposition: 5, reason: 5},
		{name: "overflow", scenario: cloudflareProcessScenario{body: append(rejected, bytes.Repeat([]byte(" "), 1<<20)...)}, disposition: 5, reason: 6},
		{name: "rejected", scenario: cloudflareProcessScenario{status: http.StatusTooManyRequests, body: rejected}, disposition: 5, reason: 7},
		{name: "transport", scenario: cloudflareProcessScenario{earlyEOF: true}, disposition: 5, reason: 8},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			test.scenario.method, test.scenario.path, test.scenario.request = http.MethodPost, createPath, requestBody
			before := serverState.set(test.scenario)
			command := cloudflareProcessCommand(implementation, intent)
			returned, code := invokeGeneratedProcess(os.Pipe, context.Background(), cloudflareProcessLauncher(t, path, installed), command, intent)
			defer clear(returned.Secret)
			if code != contract.CryptoSuccess || returned.Facts.Disposition != test.disposition || returned.Facts.Reason != test.reason ||
				returned.Facts.ResourceContractID != command.ResourceContractID || returned.Facts.LifecycleMode != command.LifecycleMode || returned.Facts.RequestDigest != command.RequestDigest || returned.Facts.IntentDigest != command.IntentDigest ||
				string(returned.Secret) != test.secret || serverState.requests.Load() != before+1 {
				t.Fatalf("real Cloudflare process differs: code=%d facts=%+v secret=%q requests=%d", code, returned.Facts, returned.Secret, serverState.requests.Load()-before)
			}

			if test.disposition == 1 || test.disposition == 2 {
				if !bytes.Equal(returned.Facts.Target, []byte(cloudflareAccount)) || !bytes.Equal(returned.Facts.ResourceData, []byte(cloudflareTokenID)) {
					t.Fatal("owned resource changed its opaque account or token binding")
				}
			} else if len(returned.Facts.Target) != 0 || len(returned.Facts.ResourceData) != 0 {
				t.Fatal("unknown result claimed an owned resource")
			}
			facts, err := contract.EncodeGeneratorSafeFacts(returned.Facts)
			if err != nil || bytes.Contains(facts, []byte(cloudflareSecret)) || bytes.Contains(facts, []byte(cloudflareBearer)) {
				t.Fatal("secret entered Cloudflare safe facts", err)
			}
		})
	}

	t.Run("delete acknowledgement", func(t *testing.T) {
		beforeCreate := serverState.set(cloudflareProcessScenario{body: complete, method: http.MethodPost, path: createPath, request: requestBody})
		create := cloudflareProcessCommand(implementation, intent)
		original, code := invokeGeneratedProcess(os.Pipe, context.Background(), cloudflareProcessLauncher(t, path, installed), create, intent)
		defer clear(original.Secret)
		if code != contract.CryptoSuccess || original.Facts.Disposition != 1 || original.Facts.Reason != 0 || string(original.Secret) != cloudflareSecret ||
			!bytes.Equal(original.Facts.Target, []byte(cloudflareAccount)) || !bytes.Equal(original.Facts.ResourceData, []byte(cloudflareTokenID)) || serverState.requests.Load() != beforeCreate+1 {
			t.Fatal("original resource evidence differs", code, original.Facts)
		}
		body := []byte(fmt.Sprintf(`{"success":true,"errors":[],"messages":[],"result":{"id":"%s"}}`, cloudflareTokenID))
		before := serverState.set(cloudflareProcessScenario{body: body, method: http.MethodDelete, path: createPath + "/" + cloudflareTokenID})
		command := cloudflareProcessCommand(implementation, intent)
		command.Action = 2
		command.AttemptID, command.TransmissionID, command.ResultID = cloudflareID("retire attempt"), cloudflareID("retire transmission"), cloudflareID("retire result")
		var err error
		command.OriginalFacts, err = contract.EncodeGeneratorSafeFacts(original.Facts)
		if err != nil {
			t.Fatal("retain original create evidence", err)
		}
		command.ResourceDigest, err = contract.GeneratorResourceDigest(original.Facts)
		if err != nil {
			t.Fatal("bind original resource", err)
		}
		target, err := contract.EncodeGeneratorTarget(contract.GeneratorTarget{Schema: contract.GeneratorTargetSchema, Name: "generated", IncarnationID: cloudflareID("incarnation"), ResourceID: cloudflareID("resource"), ConfigContractID: implementation.ConfigContractID, ResourceContractID: command.ResourceContractID, ResourceDigest: command.ResourceDigest, OriginalOperationID: create.OperationID, OriginalAttemptID: create.AttemptID, ResultContractID: command.ResultContractID, LifecycleMode: command.LifecycleMode, CompletionClass: 1})
		if err != nil {
			t.Fatal(err)
		}
		command.RequestDigest = cloudflareRequestDigest(2, intent, target)
		returned, code := invokeGeneratedProcess(os.Pipe, context.Background(), cloudflareProcessLauncher(t, path, installed), command, intent)
		defer clear(returned.Secret)
		if code != contract.CryptoSuccess || returned.Facts.Disposition != 4 || returned.Facts.Reason != 0 ||
			!bytes.Equal(returned.Facts.Target, []byte(cloudflareAccount)) || !bytes.Equal(returned.Facts.ResourceData, []byte(cloudflareTokenID)) ||
			returned.Facts.RequestDigest != command.RequestDigest || returned.Facts.IntentDigest != command.IntentDigest || len(returned.Secret) != 0 || serverState.requests.Load() != before+1 {
			t.Fatal("real Cloudflare delete acknowledgement differs", code, returned.Facts)
		}
	})

	t.Run("changed request digest", func(t *testing.T) {
		before := serverState.set(cloudflareProcessScenario{body: complete, method: http.MethodPost, path: createPath, request: requestBody})
		command := cloudflareProcessCommand(implementation, intent)
		launcher := changedCloudflareRequestLauncher{cloudflareProcessLauncher(t, path, installed)}
		returned, code := invokeGeneratedProcess(os.Pipe, context.Background(), launcher, command, intent)
		defer clear(returned.Secret)
		if code == contract.CryptoSuccess || !reflect.DeepEqual(returned.Facts, contract.GeneratorSafeFacts{}) || len(returned.Secret) != 0 || serverState.requests.Load() != before+1 {
			t.Fatal("changed request digest became an accepted result or repeated the provider request", code, returned.Facts)
		}
	})

	t.Run("changed intent digest", func(t *testing.T) {
		before := serverState.set(cloudflareProcessScenario{body: complete, method: http.MethodPost, path: createPath, request: requestBody})
		command := cloudflareProcessCommand(implementation, intent)
		command.IntentDigest[0] ^= 1
		returned, code := invokeGeneratedProcess(os.Pipe, context.Background(), cloudflareProcessLauncher(t, path, installed), command, intent)
		defer clear(returned.Secret)
		if code == contract.CryptoSuccess || !reflect.DeepEqual(returned.Facts, contract.GeneratorSafeFacts{}) || len(returned.Secret) != 0 || serverState.requests.Load() != before {
			t.Fatal("changed intent digest reached provider or became a result", code, returned.Facts)
		}
	})
}

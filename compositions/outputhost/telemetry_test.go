package outputhost

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"enkv.sh/sdk/artifact"
	protocol "enkv.sh/sdk/protocols/output"
	"enkv.sh/telemetry"
)

// full_only: false
func TestOutputHostTelemetrySeparatesPassiveCheckAndSend(t *testing.T) {
	config := testArtifactAndConfig(t)
	validator, err := NewPublicValidator(t.Context(), config.ArtifactPath, config.Installation)
	if err != nil {
		t.Fatal(err)
	}
	recorder := telemetry.NewRecorder()
	ctx := telemetry.WithCapability(context.Background(), telemetry.NewCapability(nil, recorder))
	parent := telemetry.Start(ctx, telemetry.ProviderApplication, telemetry.OpApplicationInvocation)
	request, policy := testPublicRequest(t, config.Installation.Artifact(), "fixture")
	if _, err := validator.CheckAction(parent.Context(), request, policy); err != nil {
		t.Fatal(err)
	}
	native, err := NewNative(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	command, policy, payload := testOutputCommand(t, config.Installation.Artifact(), "fixture")
	result, err := native.Dispatch(parent.Context(), command, policy, payload)
	if err != nil || result.Class != protocol.ClassAcknowledged {
		t.Fatalf("dispatch result=%#v err=%v", result, err)
	}
	parent.Finish(telemetry.ResultSuccess)
	records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 64))
	starts, returns := map[telemetry.Operation]int{}, map[telemetry.Operation]int{}
	for _, record := range records {
		if err := record.Validate(); err != nil {
			t.Fatalf("invalid output diagnostic: %v", err)
		}
		if record.Provider == telemetry.ProviderOutputHost {
			if record.Operation == telemetry.OpOutputHostPublicCheck || record.Operation == telemetry.OpOutputHostDispatch {
				if record.ParentCall != records[0].Call {
					t.Fatal("output boundary lost invocation parent")
				}
			}
			switch record.Event {
			case telemetry.DiagnosticStart:
				starts[record.Operation]++
			case telemetry.DiagnosticReturn:
				returns[record.Operation]++
			}
		}
	}
	for _, op := range []telemetry.Operation{telemetry.OpOutputHostPublicCheck, telemetry.OpOutputHostDispatch,
		telemetry.OpOutputHostHandshake, telemetry.OpOutputHostCommandSend, telemetry.OpOutputHostCredentialGate,
		telemetry.OpOutputHostResultRead, telemetry.OpOutputHostJoin} {
		if starts[op] == 0 || returns[op] != starts[op] {
			t.Fatalf("missing or unjoined output phase %s: starts=%d returns=%d", op, starts[op], returns[op])
		}
	}
	if starts[telemetry.OpOutputHostDispatch] != 1 || starts[telemetry.OpOutputHostPublicCheck] != 1 ||
		starts[telemetry.OpOutputHostCredentialGate] != 1 || starts[telemetry.OpOutputHostCancel] != 0 {
		t.Fatalf("passive check entered private/send phase: %#v", starts)
	}
	wire, err := json.Marshal(records)
	if err != nil || strings.Contains(string(wire), "private credential") || strings.Contains(string(wire), "private data") ||
		strings.Contains(string(wire), config.ArtifactPath) {
		t.Fatal("private value or host path entered output diagnostics")
	}
}

// full_only: false
func TestOutputHostTelemetryRefusalAndCredentialFailure(t *testing.T) {
	config := testArtifactAndConfig(t)
	validator, err := NewPublicValidator(t.Context(), config.ArtifactPath, config.Installation)
	if err != nil {
		t.Fatal(err)
	}
	recorder := telemetry.NewRecorder()
	ctx := telemetry.WithCapability(context.Background(), telemetry.NewCapability(nil, recorder))
	request, policy := testPublicRequest(t, config.Installation.Artifact(), "fixture")
	policy.Data = []byte("unsupported")
	request.PolicyDigest, err = protocol.PolicyDigest(request.DomainID, policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validator.CheckAction(ctx, request, policy); !errors.Is(err, ErrPassiveRefused) {
		t.Fatalf("profile refusal=%v", err)
	}
	t.Setenv("ENKV_OUTPUT_TEST_CREDENTIAL", "raw-provider-error-private-sentinel")
	native, err := NewNative(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	command, policy, payload := testOutputCommand(t, config.Installation.Artifact(), "fixture")
	if _, err := native.Dispatch(ctx, command, policy, payload); !errors.Is(err, ErrCredential) {
		t.Fatalf("credential failure=%v", err)
	}
	records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 64))
	var refused, denied bool
	for _, record := range records {
		if err := record.Validate(); err != nil {
			t.Fatal(err)
		}
		if record.Event == telemetry.DiagnosticReturn && record.Operation == telemetry.OpOutputHostPublicCheck {
			refused = record.Result == telemetry.ResultAdmissionRefused
		}
		if record.Event == telemetry.DiagnosticReturn && record.Operation == telemetry.OpOutputHostDispatch {
			denied = record.Result == telemetry.ResultDenied
		}
	}
	wire, err := json.Marshal(records)
	if err != nil || !refused || !denied || strings.Contains(string(wire), "raw-provider-error-private-sentinel") {
		t.Fatalf("unsafe or missing output failure diagnostics: refused=%t denied=%t", refused, denied)
	}
	if telemetry.Start(context.Background(), telemetry.ProviderOutputHost, telemetry.OpOutputHostDispatch) != nil {
		t.Fatal("disabled telemetry created an output call")
	}
}

// full_only: false
func TestOutputHostJoinTelemetryPreservesKnownAndUnknownTermination(t *testing.T) {
	for _, test := range []struct {
		name                 string
		waitErr              error
		contextErr           error
		cancelSignalAccepted bool
		want                 telemetry.Result
	}{
		{"completed", nil, nil, false, telemetry.ResultSuccess},
		{"canceled child", &exec.ExitError{}, context.Canceled, true, telemetry.ResultCancelled},
		{"expired child", &exec.ExitError{}, context.DeadlineExceeded, true, telemetry.ResultExpired},
		{"context ended after child", &exec.ExitError{}, context.Canceled, false, telemetry.ResultFailure},
		{"nonzero child", &exec.ExitError{}, nil, false, telemetry.ResultFailure},
		{"wait unavailable", errors.New("raw-provider-error-private-sentinel"), nil, true, telemetry.ResultEvidenceUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			recorder := telemetry.NewRecorder()
			ctx := telemetry.WithCapability(context.Background(), telemetry.NewCapability(nil, recorder))
			call := telemetry.Start(ctx, telemetry.ProviderOutputHost, telemetry.OpOutputHostJoin)
			finishOutputJoin(call, test.waitErr, test.contextErr, test.cancelSignalAccepted)
			records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 2))
			if len(records) != 2 || records[1].Result != test.want || records[1].Validate() != nil {
				t.Fatalf("join diagnostic=%+v", records)
			}
			wire, err := json.Marshal(records)
			if err != nil || strings.Contains(string(wire), "raw-provider-error-private-sentinel") {
				t.Fatal("raw Wait error entered diagnostics")
			}
		})
	}
}

// full_only: false
func TestOutputHostEarlyChildExitIsNotCancellation(t *testing.T) {
	config := testArtifactAndConfig(t)
	build := exec.Command("go", "build", "-trimpath", "-ldflags=-X main.exitBeforeHello=1", "-o", config.ArtifactPath, "./cmd/enkv-output-contract-test")
	build.Dir = filepath.Join("..", "..", "tests", "fixtures", "output-contract-test")
	build.Env = append(os.Environ(), "GOWORK=off", "GOTOOLCHAIN=local")
	build.Args = append(build.Args[:2], append([]string{"-modfile=" + config.ArtifactPath + ".mod"}, build.Args[2:]...)...)
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build early-exit child: %v: %s", err, output)
	}
	if err := os.Chmod(config.ArtifactPath, 0700); err != nil {
		t.Fatal(err)
	}

	descriptorBody, err := os.ReadFile(filepath.Join(build.Dir, "cmd", "enkv-output-contract-test", "plugin.json"))
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := artifact.DecodeDescriptor(descriptorBody)
	if err != nil {
		t.Fatal(err)
	}
	config.Installation = testBindExecutable(t, config.ArtifactPath, build.Dir, descriptor, false)

	for _, passive := range []bool{false, true} {
		name := "send"
		if passive {
			name = "passive"
		}
		t.Run(name, func(t *testing.T) {
			recorder := telemetry.NewRecorder()
			ctx := telemetry.WithCapability(context.Background(), telemetry.NewCapability(nil, recorder))
			if passive {
				validator, err := NewPublicValidator(t.Context(), config.ArtifactPath, config.Installation)
				if err != nil {
					t.Fatal(err)
				}
				request, policy := testPublicRequest(t, config.Installation.Artifact(), "fixture")
				_, err = validator.CheckAction(ctx, request, policy)
				if err == nil {
					t.Fatal("early child exit accepted")
				}
			} else {
				native, err := NewNative(t.Context(), config)
				if err != nil {
					t.Fatal(err)
				}
				command, policy, payload := testOutputCommand(t, config.Installation.Artifact(), "fixture")
				_, err = native.Dispatch(ctx, command, policy, payload)
				if err == nil {
					t.Fatal("early child exit accepted")
				}
			}
			var joined bool
			for _, record := range recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 16)) {
				if err := record.Validate(); err != nil {
					t.Fatal(err)
				}
				if record.Operation == telemetry.OpOutputHostJoin && record.Event == telemetry.DiagnosticReturn {
					joined = true
					if record.Result != telemetry.ResultFailure {
						t.Fatalf("known early nonzero exit classified %s", record.Result)
					}
				}
			}
			if !joined {
				t.Fatal("early child was not joined")
			}
		})
	}
}

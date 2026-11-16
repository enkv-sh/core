package outputhost

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"enkv.sh/sdk/artifact"
	protocol "enkv.sh/sdk/protocols/output"
	"enkv.sh/telemetry"
)

// full_only: false
func TestPassiveOutputFailureStages(t *testing.T) {
	config := testArtifactAndConfig(t)
	validator, err := NewPublicValidator(t.Context(), config.ArtifactPath, config.Installation)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("local-invalid", func(t *testing.T) {
		action, policy := testPublicRequest(t, config.Installation.Artifact(), "fixture")
		action.Schema = 0
		checks := []func() error{
			func() error { _, err := validator.Normalize(t.Context(), protocol.NormalizeRequest{}); return err },
			func() error {
				_, err := validator.ValidateCanonical(t.Context(), protocol.CanonicalRequest{})
				return err
			},
			func() error {
				_, err := validator.InterpretTarget(t.Context(), protocol.InterpretRequest{})
				return err
			},
			func() error { _, err := validator.CheckAction(t.Context(), action, policy); return err },
		}
		for _, check := range checks {
			err := check()
			if !errors.Is(err, protocol.ErrProtocol) || errors.Is(err, ErrProcess) || errors.Is(err, ErrPassiveRefused) {
				t.Errorf("local request acquired hosted evidence: %v", err)
			}
		}
		assertNoStagedChild(t, config.ArtifactPath)
	})
	for _, mode := range []string{"refusal", "illegal-facts", "wrong-digest", "malformed", "trailing", "process-failure", "config-mismatch"} {
		t.Run(mode, func(t *testing.T) {
			build := exec.CommandContext(t.Context(), "go", "build", "-trimpath", "-buildvcs=false", "-modfile="+config.ArtifactPath+".mod", "-ldflags=-X main.publicFailureMode="+mode, "-o", config.ArtifactPath, "./cmd/enkv-output-contract-test")
			build.Dir = filepath.Join("..", "..", "tests", "fixtures", "output-contract-test")
			build.Env = testOutputBuildEnvironment(false)
			if out, err := build.CombinedOutput(); err != nil {
				t.Fatalf("build public fault child: %v: %s", err, out)
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
			validator, err := NewPublicValidator(t.Context(), config.ArtifactPath, config.Installation)
			if err != nil {
				t.Fatal(err)
			}
			for _, operation := range []string{"normalize", "canonical", "interpret", "action"} {
				if mode == "config-mismatch" && operation != "normalize" {
					continue
				}
				t.Run(operation, func(t *testing.T) {
					recorder := telemetry.NewRecorder()
					ctx := telemetry.WithCapability(context.Background(), telemetry.NewCapability(nil, recorder))
					action, policy := testPublicRequest(t, config.Installation.Artifact(), "fixture")
					destination := protocol.Destination{ConfigContractID: "test-output/config/v1", ServiceContractID: "test-output/service/v1", CanonicalSettings: []byte(`{"prefix":"fixture"}`), Policy: protocol.Policy{ContractID: "test-policy", Data: []byte("1,9")}, Capabilities: action.Target.Capabilities}
					var callErr error
					switch operation {
					case "normalize":
						_, callErr = validator.Normalize(ctx, protocol.NormalizeRequest{Schema: 1, DeadlineUnixMillis: testDeadline(), Settings: []byte(`{"prefix":"fixture"}`)})
					case "canonical":
						_, callErr = validator.ValidateCanonical(ctx, protocol.CanonicalRequest{Schema: 1, DeadlineUnixMillis: testDeadline(), Destination: destination})
					case "interpret":
						_, callErr = validator.InterpretTarget(ctx, protocol.InterpretRequest{Schema: 1, DeadlineUnixMillis: testDeadline(), Destination: destination, EntryName: "value", PayloadEncoding: protocol.EncodingRaw})
					case "action":
						_, callErr = validator.CheckAction(ctx, action, policy)
					}
					wantResult := telemetry.ResultEvidenceUnavailable
					if mode == "refusal" {
						wantResult = telemetry.ResultAdmissionRefused
						if !errors.Is(callErr, ErrPassiveRefused) || errors.Is(callErr, ErrAdmission) || errors.Is(callErr, ErrProcess) {
							t.Errorf("valid refusal lost its category: %v", callErr)
						}
					} else {
						if !errors.Is(callErr, ErrProcess) || errors.Is(callErr, ErrAdmission) || errors.Is(callErr, ErrPassiveRefused) {
							t.Errorf("failed exchange acquired refusal category: %v", callErr)
						}
						if mode != "process-failure" && !errors.Is(callErr, protocol.ErrProtocol) {
							t.Errorf("protocol failure cause lost: %v", callErr)
						}
					}
					assertNoStagedChild(t, config.ArtifactPath)
					joined, returned := false, false
					for _, record := range recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 32)) {
						if err := record.Validate(); err != nil {
							t.Fatal(err)
						}
						if record.Event != telemetry.DiagnosticReturn {
							continue
						}
						if record.Operation == telemetry.OpOutputHostJoin {
							joined = true
						}
						if record.Operation == telemetry.OpOutputHostPublicCheck {
							returned = true
							if record.Result != wantResult {
								t.Errorf("public diagnostic=%s want %s", record.Result, wantResult)
							}
						}
					}
					if !joined || !returned {
						t.Error("passive result lost positive process join or public terminal")
					}
				})
			}
		})
	}
}

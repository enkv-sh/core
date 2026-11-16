package outputhost

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"

	protocol "enkv.sh/sdk/protocols/output"
	"enkv.sh/telemetry"
)

// full_only: false
func TestOutputAdmissionUsesDeclaredNamespaceWithoutCatalog(t *testing.T) {
	for _, name := range []string{"my-local-output", "modified-service-output"} {
		m, _, _ := fixtureOutputInstallation(t, 0, "example.invalid/independent/output/tools/deliver")
		descriptor := fixtureOutputDescriptor(name)
		descriptor.Output.ConfigContractID = "unpublished/semantic-contract/v17"
		m, dependency := bindOutputMetadata(t, m, descriptor)
		installed, err := NewInstallation(m, dependency)
		if err != nil || installed.Artifact().ConfigContractID != descriptor.Output.ConfigContractID {
			t.Fatal("private namespace refused", err)
		}
	}
}
func testDeadline() uint64 { return uint64(time.Now().Add(10 * time.Second).UnixMilli()) }

func testPublicRequest(t *testing.T, a Artifact, target string) (protocol.ActionCheckRequest, protocol.Policy) {
	t.Helper()
	command, policy, _ := testOutputCommand(t, a, target)
	return protocol.ActionCheckRequest{Schema: 1, Action: command.Action, DomainID: command.DomainID, DescriptorID: a.DescriptorID, Target: command.Target, PolicyDigest: command.PolicyDigest, PolicyContractID: policy.ContractID, PayloadLengthMode: protocol.LengthExact, PayloadLength: command.PayloadLength, DeadlineUnixMillis: command.DeadlineUnixMillis}, policy
}

// full_only: false
func TestPassiveOutputHasNoCredentialOrSendRightAndJoins(t *testing.T) {
	config := testArtifactAndConfig(t)
	t.Setenv("ENKV_OUTPUT_TEST_CREDENTIAL", "")
	validator, err := NewPublicValidator(t.Context(), config.ArtifactPath, config.Installation)
	if err != nil {
		t.Fatal(err)
	}
	request, policy := testPublicRequest(t, config.Installation.Artifact(), "fixture")
	wrongDescriptor := request
	wrongDescriptor.DescriptorID[0] ^= 1
	if _, err := validator.CheckAction(context.Background(), wrongDescriptor, policy); !errors.Is(err, ErrAdmission) {
		t.Fatalf("wrong descriptor admitted in passive check: %v", err)
	}
	result, err := validator.CheckAction(context.Background(), request, policy)
	if err != nil || !result.Accepted || result.PayloadBounds.Minimum != 0 || result.PayloadBounds.Maximum != protocol.MaximumPayloadBytes {
		t.Fatalf("public result=%#v err=%v", result, err)
	}
	request.PayloadLengthMode, request.PayloadLength = protocol.LengthExact, 12
	if _, err := validator.CheckAction(context.Background(), request, policy); err != nil {
		t.Fatal(err)
	}
	assertNoStagedChild(t, config.ArtifactPath)
}

// full_only: false
func TestPassiveOutputCancellationJoinsWithoutCredential(t *testing.T) {
	config := testArtifactAndConfig(t)
	validator, err := NewPublicValidator(t.Context(), config.ArtifactPath, config.Installation)
	if err != nil {
		t.Fatal(err)
	}
	request, policy := testPublicRequest(t, config.Installation.Artifact(), "sleep")
	request.Target.CanonicalTarget, request.Target.ConsumerLocator = "public-sleep", "public-sleep"
	recorder := telemetry.NewRecorder()
	base := telemetry.WithCapability(context.Background(), telemetry.NewCapability(nil, recorder))
	ctx, cancel := context.WithTimeout(base, time.Second)
	defer cancel()
	if _, err := validator.CheckAction(ctx, request, policy); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancellation err=%v", err)
	}
	assertNoStagedChild(t, config.ArtifactPath)
	joined, reportedSuccessfulCompletion, expired := false, false, false
	for _, record := range recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 32)) {
		if err := record.Validate(); err != nil {
			t.Fatal(err)
		}
		if record.Operation == telemetry.OpOutputHostJoin && record.Event == telemetry.DiagnosticReturn {
			joined = true
			reportedSuccessfulCompletion = record.Result == telemetry.ResultSuccess
		}
		if record.Operation == telemetry.OpOutputHostPublicCheck && record.Event == telemetry.DiagnosticReturn {
			expired = record.Result == telemetry.ResultExpired
		}
	}
	if !joined || reportedSuccessfulCompletion || !expired {
		t.Fatal("ordinary passive expiry lost its join or Expired disposition")
	}
}

// full_only: false
func TestPassiveStagingCleanupFailureIsOperational(t *testing.T) {
	config := testArtifactAndConfig(t)
	validator, err := NewPublicValidator(t.Context(), config.ArtifactPath, config.Installation)
	if err != nil {
		t.Fatal(err)
	}
	staging := ""
	defer func() {
		if staging != "" {
			if err := os.Chmod(staging, 0700); err != nil {
				t.Errorf("restore staging permission: %v", err)
			}
		}
	}()
	request, policy := testPublicRequest(t, config.Installation.Artifact(), "deny-cleanup")
	recorder := telemetry.NewRecorder()
	ctx := telemetry.WithCapability(context.Background(), telemetry.NewCapability(nil, recorder))
	if _, err := validator.CheckAction(ctx, request, policy); !errors.Is(err, ErrProcess) || errors.Is(err, ErrAdmission) {
		t.Fatalf("cleanup failure classified as %v", err)
	}
	roots := stagedOutputRoots(t, config.ArtifactPath)
	if len(roots) != 1 {
		t.Fatalf("cleanup failure retained %d roots, want one", len(roots))
	}
	staging = roots[0]
	info, err := os.Stat(staging)
	if err != nil || info.Mode().Perm() != 0500 {
		t.Fatalf("test child did not deny staging cleanup: mode=%v err=%v", info, err)
	}
	seen := false
	for _, record := range recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 16)) {
		if err := record.Validate(); err != nil {
			t.Fatal(err)
		}
		if record.Operation == telemetry.OpOutputHostPublicCheck && record.Event == telemetry.DiagnosticReturn {
			seen = true
			if record.Result != telemetry.ResultEvidenceUnavailable {
				t.Fatalf("cleanup diagnostic classified as %s", record.Result)
			}
		}
	}
	if !seen {
		t.Fatal("missing passive cleanup diagnostic")
	}
}

// full_only: false
func TestPassiveOutputCancellationOwnsEachEndpoint(t *testing.T) {
	for _, mode := range []string{"control", "result", "result-short", "result-eof"} {
		t.Run(mode, func(t *testing.T) {
			listener := endpointHolderListener(t, t.TempDir())
			config := testArtifactAndConfig(t, mode, listener.Addr().String())
			validator, err := NewPublicValidator(t.Context(), config.ArtifactPath, config.Installation)
			if err != nil {
				t.Fatal(err)
			}
			request, policy := testPublicRequest(t, config.Installation.Artifact(), "fixture")
			if mode == "control" {
				policy.Data = bytes.Repeat([]byte{'p'}, protocol.MaximumPolicyBytes-256)
				request.PolicyDigest, err = protocol.PolicyDigest(request.DomainID, policy)
				if err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				result, err := validator.CheckAction(ctx, request, policy)
				if result != (protocol.ActionCheckResult{}) {
					err = errors.Join(err, errors.New("canceled passive reply was exposed"))
				}
				done <- err
			}()
			holder := receiveHeldEndpoint(t, listener)
			assertEndpointCancellation(t, cancel, done, holder)
			assertNoStagedChild(t, config.ArtifactPath)
		})
	}
}

// full_only: false
func TestPassivePolicyActionHasNoCredentialAndJoins(t *testing.T) {
	config := testArtifactAndConfig(t)
	t.Setenv("ENKV_OUTPUT_TEST_CREDENTIAL", "")
	validator, err := NewPublicValidator(t.Context(), config.ArtifactPath, config.Installation)
	if err != nil {
		t.Fatal(err)
	}
	action, policy := testPublicRequest(t, config.Installation.Artifact(), "fixture")
	request := protocol.PolicyActionRequest{Schema: 1, DeadlineUnixMillis: action.DeadlineUnixMillis, DomainID: action.DomainID,
		DescriptorID: action.DescriptorID, PolicyDigest: action.PolicyDigest, PolicyContractID: action.PolicyContractID, Target: action.Target}
	for _, present := range []bool{false, true} {
		request.HasPreviousPolicyDigest = present
		request.PreviousPolicyDigest = protocol.ID{}
		if present {
			request.PreviousPolicyDigest[0] = 1
		}
		recorder := telemetry.NewRecorder()
		ctx := telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder))
		result, err := validator.SelectPolicyAction(ctx, request, policy)
		if err != nil || !result.Accepted || result.Action != protocol.ActionUpdatePolicy {
			t.Fatal("passive policy action", result, err)
		}
		joined := false
		for _, record := range recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 32)) {
			if record.Operation == telemetry.OpOutputHostJoin && record.Event == telemetry.DiagnosticReturn && record.Result == telemetry.ResultSuccess {
				joined = true
			}
		}
		if !joined {
			t.Fatal("passive policy choice lost positive child join")
		}
	}
	bad := request
	bad.DescriptorID[0] ^= 1
	if _, err := validator.SelectPolicyAction(t.Context(), bad, policy); !errors.Is(err, ErrAdmission) {
		t.Fatal("wrong descriptor reached selector", err)
	}
	bad = request
	bad.PolicyDigest[0] ^= 1
	if _, err := validator.SelectPolicyAction(t.Context(), bad, policy); err == nil {
		t.Fatal("wrong policy bytes reached selector")
	}
	assertNoStagedChild(t, config.ArtifactPath)
}

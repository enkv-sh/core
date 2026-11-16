package compositionfull

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// full_only: false
func TestInitializationPreDeliveryRefusalDoesNotClaimDeliveryFailure(t *testing.T) {
	for _, format := range []configuration.Format{configuration.JSON, configuration.YAML} {
		for _, condition := range []string{"capture", "declaration"} {
			t.Run(fmt.Sprintf("%d/%s", format, condition), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				path := filepath.Join(t.TempDir(), "configuration")
				body := []byte(`{"secret-sentinel":"raw-parser-error-sentinel"}`)
				if condition == "declaration" {
					body = initializationSetupSource(t, "aws", false, true)
				}
				if err := os.WriteFile(path, body, 0600); err != nil {
					t.Fatal(err)
				}
				result, cause := initializeConfiguration(ctx, path, format, func(context.Context, *configuration.Model) (initializationResources, error) {
					t.Fatal("pre-delivery refusal constructed a provider")
					return initializationResources{}, nil
				})
				if cause == nil || result.PreAdmission == nil || result.PreAdmission.Stage != condition || result.StateResult != contract.InitializationRefused {
					t.Fatal("actual pre-delivery refusal fixture did not reach its boundary", result.PreAdmission, cause)
				}
				machine, err := RenderInitializationJSON(result, cause)
				var wire struct {
					State    string `json:"state_result"`
					Delivery struct {
						Outcome        string `json:"outcome"`
						RecoverySource string `json:"recovery_source"`
						CleanupFailed  bool   `json:"cleanup_failed"`
					} `json:"local_delivery"`
				}
				if err != nil || json.Unmarshal(machine, &wire) != nil || wire.State != "refused" || wire.Delivery.Outcome != "not-attempted" || wire.Delivery.RecoverySource != "" || wire.Delivery.CleanupFailed || InitializationExitCode(result, cause) != 2 {
					t.Fatal("pre-delivery error became an attempted delivery", err, string(machine))
				}
				human, err := RenderInitializationHuman(result, cause)
				if err != nil || !bytes.Contains(human, []byte("Local files: not-attempted\n")) {
					t.Fatal("human delivery fact differs", err)
				}
				actual, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(actual, body) {
					t.Fatal("refused initialization changed source", err)
				}
			})
		}
	}
}

func initializationRenderingFixture(t *testing.T) InitializationResult {
	t.Helper()
	id := func(n byte) contract.ID { return contract.ID{n} }
	receipt, err := contract.GenesisReceiptFields(id(1), id(2), id(3))
	if err != nil {
		t.Fatal(err)
	}
	receipt.RequestIdentityDigest = id(4)
	receipt.CompleteResult = contract.GeneratorDescriptor{Digest: id(5), Length: 655, Count: 1}
	body, err := contract.EncodeCompactMutationReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	// This synthetic public carrier tests rendering only; it grants no admission.
	return InitializationResult{PublicInitializationResult: core.PublicInitializationResult{
		Result:      core.Result{Outcome: core.ObservedCurrent, Evidence: core.AuthenticatedClosure, RequestedRevision: id(3), ObservedRevision: id(3), ObservedSnapshotID: id(6)},
		OperationID: id(2), RequestIdentity: id(4), StateResult: contract.InitializationSuccess, EffectSummary: "effect-no-change", Receipt: body,
		Payload: &contract.InitPayload{InitID: id(2), DomainID: id(1), DescriptorArtifactID: id(7), ManifestArtifactID: id(8), DescriptorDigest: id(9), StoreID: id(10), HeadRevisionID: id(3), SnapshotID: id(6)}},
		EditablePath: "/source/config.json", GeneratedPath: "/source/.enkv/generated.json", ManifestPath: "/source/.enkv/manifest.init", DeliveryAttempted: true}
}

// full_only: false
func TestInitializationRenderingPreservesReadyAndFailureMeanings(t *testing.T) {
	for _, state := range []contract.InitializationStateResult{contract.InitializationSuccess, contract.InitializationExactResume, contract.InitializationRefused, contract.InitializationUnavailable, contract.InitializationContention, contract.InitializationCommitUnknown, contract.InitializationPositiveDefect} {
		t.Run(string(state), func(t *testing.T) {
			result := initializationRenderingFixture(t)
			result.StateResult = state
			ready := state == contract.InitializationSuccess || state == contract.InitializationExactResume
			wantCode := 0
			if !ready {
				result.Payload, result.Receipt = nil, nil
				result.Result = core.Result{Outcome: map[contract.InitializationStateResult]core.Outcome{contract.InitializationRefused: core.AdmissionRefused, contract.InitializationUnavailable: core.EvidenceUnavailable, contract.InitializationContention: core.Contention, contract.InitializationCommitUnknown: core.UnresolvedCommit, contract.InitializationPositiveDefect: core.IntegrityFailure}[state]}
				if state == contract.InitializationCommitUnknown {
					result.Result.CommitMayHaveOccurred = true
				}
				wantCode = 2
				if state == contract.InitializationUnavailable || state == contract.InitializationContention || state == contract.InitializationCommitUnknown {
					wantCode = 3
				}
			}
			machine, err := RenderInitializationJSON(result, nil)
			if err != nil {
				t.Fatal(err)
			}
			human, err := RenderInitializationHuman(result, nil)
			if err != nil {
				t.Fatal(err)
			}
			var wire struct {
				Schema           string `json:"schema"`
				Operation        string `json:"operation_kind"`
				State            string `json:"state_result"`
				Effect           string `json:"effect_summary"`
				Output           string `json:"output_summary"`
				OperationPayload string `json:"operation_payload"`
				Payload          *struct {
					Schema   string `json:"schema"`
					Revision string `json:"ready_head_revision_id"`
				} `json:"payload"`
				Receipt  string `json:"receipt_hex"`
				Delivery struct {
					Editable  string `json:"editable_path"`
					Generated string `json:"generated_path"`
					Manifest  string `json:"manifest_path"`
				} `json:"local_delivery"`
			}
			if json.Unmarshal(machine, &wire) != nil || wire.Schema != "ProductResult/v1" || wire.Operation != "initialize-empty-domain" || wire.State != string(state) || wire.Effect != "effect-no-change" || wire.Output != "not-applicable" || InitializationExitCode(result, nil) != wantCode {
				t.Fatal("wrong public initialization result", string(machine))
			}
			if wire.Delivery.Editable != result.EditablePath || wire.Delivery.Generated != result.GeneratedPath || wire.Delivery.Manifest != result.ManifestPath {
				t.Fatal("delivery paths were lost on remote outcome")
			}
			if ready {
				if wire.OperationPayload != "InitPayload/v1" || wire.Payload == nil || wire.Payload.Schema != "InitPayload/v1" || wire.Payload.Revision != hex.EncodeToString(result.Payload.HeadRevisionID[:]) || wire.Receipt != hex.EncodeToString(result.Receipt) {
					t.Fatal("ready payload or exact stored receipt changed")
				}
			} else if wire.OperationPayload != "none" || wire.Payload != nil || wire.Receipt != "" {
				t.Fatal("nonready outcome disclosed ready payload")
			}
			for _, text := range []string{"Initialization: " + string(state), result.GeneratedPath, result.EditablePath} {
				if !bytes.Contains(human, []byte(text)) {
					t.Fatal("human output lost result fact", text)
				}
			}
			if bytes.Contains(human, []byte(result.ManifestPath)) {
				t.Fatal("human initialization exposed the routine manifest path")
			}
		})
	}
}

// full_only: false
func TestInitializationRenderingRejectsContradictoryCarriers(t *testing.T) {
	for _, change := range []func(*InitializationResult){
		func(r *InitializationResult) { r.Payload = nil },
		func(r *InitializationResult) { r.Result.Evidence = core.NoEvidence },
		func(r *InitializationResult) { r.Result.CommitMayHaveOccurred = true },
		func(r *InitializationResult) { r.OperationID = contract.ID{99} },
		func(r *InitializationResult) { r.RequestIdentity = contract.ID{99} },
		func(r *InitializationResult) { r.Payload.HeadRevisionID = contract.ID{99} },
		func(r *InitializationResult) { r.Receipt = append(r.Receipt, 0) },
		func(r *InitializationResult) {
			r.StateResult = contract.InitializationUnavailable
			r.Result.Outcome = core.EvidenceUnavailable
		},
		func(r *InitializationResult) { r.StateResult = "raw-error-sentinel" },
		func(r *InitializationResult) { r.EffectSummary = "raw-error-sentinel" },
	} {
		result := initializationRenderingFixture(t)
		change(&result)
		if body, err := RenderInitializationJSON(result, nil); err == nil || len(body) != 0 {
			t.Fatal("invalid machine result accepted")
		}
		if body, err := RenderInitializationHuman(result, nil); err == nil || len(body) != 0 {
			t.Fatal("invalid human result accepted")
		}
		if InitializationExitCode(result, nil) != 2 {
			t.Fatal("invalid result returned success")
		}
	}
}

// full_only: false
func TestInitializationRenderingKeepsLocalDeliverySeparateAndSafe(t *testing.T) {
	result := initializationRenderingFixture(t)
	result.EditablePath = "/source\nwarning: invented"
	for _, local := range []struct {
		name    string
		err     error
		code    int
		outcome string
	}{
		{"known", errors.New("raw-error-sentinel secret-sentinel"), 2, "failed"},
		{"unknown", errors.Join(errors.New("raw-error-sentinel secret-sentinel"), &configuration.UnknownEdit{}), 3, "unknown"},
	} {
		t.Run(local.name, func(t *testing.T) {
			machine, err := RenderInitializationJSON(result, local.err)
			if err != nil {
				t.Fatal(err)
			}
			human, err := RenderInitializationHuman(result, local.err)
			if err != nil {
				t.Fatal(err)
			}
			var record struct {
				State    string          `json:"state_result"`
				Payload  json.RawMessage `json:"payload"`
				Delivery struct {
					Outcome  string `json:"outcome"`
					Editable string `json:"editable_path"`
				} `json:"local_delivery"`
			}
			if json.Unmarshal(machine, &record) != nil || record.State != "success" || len(record.Payload) == 0 || record.Delivery.Outcome != local.outcome || record.Delivery.Editable != result.EditablePath || InitializationExitCode(result, local.err) != local.code {
				t.Fatal("local failure changed the canonical outcome or discarded paths")
			}
			if strings.Contains(string(human), "/source\n") {
				t.Fatal("path created a human output line")
			}
			for _, body := range [][]byte{machine, human} {
				if bytes.Contains(body, []byte("raw-error-sentinel")) || bytes.Contains(body, []byte("secret-sentinel")) {
					t.Fatal("raw error escaped local delivery")
				}
			}
		})
	}
}

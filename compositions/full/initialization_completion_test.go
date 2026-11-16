package compositionfull

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// full_only: false
func TestInitializationCompletionKeepsConstructedIdentityOnFailures(t *testing.T) {
	t.Run("before-request", func(t *testing.T) {
		correlation, err := NewInitializationRefusal(configuration.JSON)
		if err != nil {
			t.Fatal(err)
		}
		result := InitializationResult{PublicInitializationResult: core.PublicInitializationResult{
			StateResult: contract.InitializationRefused, EffectSummary: "effect-no-change", Result: core.Result{Outcome: core.AdmissionRefused}}}
		finishInitializationPreAdmission(&result, correlation.OperationID, correlation.PreAdmission)
		body, err := RenderInitializationJSON(result, nil)
		var wire struct {
			Identity struct {
				Schema string `json:"schema"`
			} `json:"request_identity"`
			Replay string `json:"replay_identity"`
		}
		if err != nil || result.OperationID != correlation.OperationID || !result.RequestIdentity.IsZero() || result.PreAdmission == nil || json.Unmarshal(body, &wire) != nil || wire.Identity.Schema != "PreAdmissionRequestIdentity/v1" || wire.Replay != "none" {
			t.Fatal("pre-request failure lost correlation or claimed constructed identity", err)
		}
	})
	for _, row := range []struct {
		name    string
		state   contract.InitializationStateResult
		outcome core.Outcome
	}{
		{"refused", contract.InitializationRefused, core.AdmissionRefused},
		{"unavailable", contract.InitializationUnavailable, core.EvidenceUnavailable},
		{"contention", contract.InitializationContention, core.Contention},
		{"unknown", contract.InitializationCommitUnknown, core.UnresolvedCommit},
	} {
		t.Run(row.name, func(t *testing.T) {
			correlation, err := NewInitializationRefusal(configuration.JSON)
			if err != nil {
				t.Fatal(err)
			}
			// These literals are the facts returned by Core after request
			// construction. The Core integration regression checks their origin.
			operation, request := contract.ID{17}, contract.ID{23}
			result := correlation
			result.PublicInitializationResult = core.PublicInitializationResult{OperationID: operation, RequestIdentity: request,
				StateResult: row.state, EffectSummary: "effect-no-change", Result: core.Result{Outcome: row.outcome, CommitMayHaveOccurred: row.outcome == core.UnresolvedCommit}}
			finishInitializationPreAdmission(&result, correlation.OperationID, correlation.PreAdmission)
			if result.PreAdmission != nil || result.OperationID != operation || result.RequestIdentity != request {
				t.Fatal("composition completion replaced constructed request facts")
			}
			body, err := RenderInitializationJSON(result, nil)
			if err != nil {
				t.Fatal("constructed failure result is not renderable", err)
			}
			var wire struct {
				Operation string `json:"operation_id"`
				Identity  string `json:"request_identity"`
				State     string `json:"state_result"`
				Variant   string `json:"operation_payload"`
				Payload   any    `json:"payload"`
				Receipt   string `json:"receipt_hex"`
				Unknown   bool   `json:"commit_may_have_occurred"`
			}
			if json.Unmarshal(body, &wire) != nil || wire.Operation != hex.EncodeToString(operation[:]) || wire.Identity != hex.EncodeToString(request[:]) || wire.State != string(row.state) || wire.Variant != "none" || wire.Payload != nil || wire.Receipt != "" || wire.Unknown != (row.outcome == core.UnresolvedCommit) {
				t.Fatal("failure rendering lost exact identity or fabricated success facts")
			}
			human, err := RenderInitializationHuman(result, nil)
			if err != nil || !bytes.Contains(human, []byte(hex.EncodeToString(request[:]))) || !bytes.Contains(human, []byte(string(row.state))) {
				t.Fatal("human failure rendering lost constructed identity", err)
			}
			if row.outcome == core.UnresolvedCommit {
				result.RequestIdentity = contract.ID{}
				finishInitializationPreAdmission(&result, correlation.OperationID, correlation.PreAdmission)
				if _, err := RenderInitializationJSON(result, nil); err == nil {
					t.Error("unknown outcome was accepted with pre-admission identity")
				}
			}
		})
	}
}

package compositionfull

import (
	"bytes"
	"context"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// full_only: false
func TestConfigurationAccessMutationsKeepInterruptionCause(t *testing.T) {
	for _, operation := range []struct {
		name      string
		renderers []func(core.PublicApplyResult) ([]byte, error)
	}{
		{"rekey", []func(core.PublicApplyResult) ([]byte, error){RenderEnvelopeRekeyJSON, RenderEnvelopeRekeyHuman}},
		{"retire", []func(core.PublicApplyResult) ([]byte, error){RenderRecipientRetirementJSON, RenderRecipientRetirementHuman}},
	} {
		for _, reason := range []contract.DiagnosticReason{contract.ReasonCancelled, contract.ReasonExpired} {
			t.Run(operation.name+"/"+string(reason), func(t *testing.T) {
				request := contract.ID{1}
				correlation, err := newConfigurationApplyResult(request, configuration.JSON)
				if err != nil {
					t.Fatal(err)
				}
				result := core.PublicApplyResult{RequestID: request, Result: core.Result{Outcome: core.AdmissionRefused, Reason: core.AdmissionInvalid},
					Preparation: &core.ApplyPreparationFacts{}, Diagnostics: []contract.Diagnostic{{Subject: contract.DiagnosticSubject{Kind: contract.SubjectObservation},
						Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: reason}}}
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				if reason == contract.ReasonExpired {
					var stop context.CancelFunc
					ctx, stop = context.WithDeadline(t.Context(), time.Unix(1, 0))
					defer stop()
				}
				got := finishConfigurationAccessMutation(ctx, result, correlation, operation.name)
				if got.PreAdmission == nil || got.PreAdmission.Code != string(reason) || got.PreAdmission.Stage != operation.name || got.OperationID != correlation.OperationID || got.RequestID != request || got.RequestIdentity != result.RequestIdentity || got.Result != result.Result || got.Preparation != result.Preparation || len(got.Diagnostics) != 1 || got.Diagnostics[0].Reason != reason {
					t.Errorf("access adapter replaced the actual interruption cause or result: %+v", got)
				}
				for _, render := range operation.renderers {
					body, err := render(got)
					if err != nil || !bytes.Contains(body, []byte(reason)) || bytes.Contains(body, []byte("invalid-input")) {
						t.Error("access interruption projection lost the cause", err)
					}
				}
			})
		}
	}
}

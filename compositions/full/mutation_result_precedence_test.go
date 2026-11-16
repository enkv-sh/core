package compositionfull

import (
	"testing"

	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// full_only: false
func TestMutationExitCodeKeepsRetainedUncertaintyBeforeRefusal(t *testing.T) {
	for _, row := range []struct {
		name    string
		outcome core.Outcome
		state   string
		effect  uint16
		want    int
	}{
		{"refused-unknown", core.AdmissionRefused, "refused", contract.ReceiptEffectUnknown, 3},
		{"refused-pending", core.AdmissionRefused, "refused", contract.ReceiptEffectPending, 3},
		{"refused-partial", core.AdmissionRefused, "refused", contract.ReceiptEffectPartial, 3},
		{"defect-unknown", core.IntegrityFailure, "positive-defect", contract.ReceiptEffectUnknown, 3},
		{"refused-terminal", core.AdmissionRefused, "refused", contract.ReceiptEffectFailed, 2},
		{"selected-terminal", core.ObservedCurrent, "effect-terminal-failure", contract.ReceiptEffectFailed, 2},
		{"selected-complete", core.ObservedCurrent, "success", contract.ReceiptEffectComplete, 0},
		{"unavailable-complete", core.EvidenceUnavailable, "unavailable", contract.ReceiptEffectComplete, 3},
		{"terminal-with-unable", core.AdmissionRefused, "refused", contract.ReceiptEffectFailed, 3},
	} {
		t.Run(row.name, func(t *testing.T) {
			out := core.PublicApplyResult{Result: core.Result{Outcome: row.outcome}, Generated: &core.GeneratedInvocationResult{StateResult: row.state, EffectSummary: row.effect}}
			if row.name == "terminal-with-unable" {
				out.Diagnostics = []contract.Diagnostic{{Subject: contract.DiagnosticSubject{Kind: contract.SubjectObservation}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonExpired}}
			}
			if got := MutationExitCode(out); got != row.want {
				t.Fatal("canonical stop hid retained effect meaning", got, row.want)
			}
			if out.Result.Outcome != row.outcome || out.Generated.StateResult != row.state || out.Generated.EffectSummary != row.effect {
				t.Fatal("exit classification changed result facts")
			}
		})
	}
}

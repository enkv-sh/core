package compositionfull

import (
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// MutationExitCode reports the command status for the mutation's selected facts,
// generated progress and diagnostics.
func MutationExitCode(r core.PublicApplyResult) int {
	code := 2
	switch r.Result.Outcome {
	case core.ObservedCurrent, core.Unchanged:
		code = 0
	case core.EvidenceUnavailable, core.UnresolvedCommit, core.Contention:
		code = 3
	}
	if code == 3 {
		return code
	}
	if g := r.Generated; g != nil {
		stateCode, known := generatedStateExitCode(g.StateResult)
		if !known {
			return 2
		}
		switch g.EffectSummary {
		case contract.ReceiptEffectPending, contract.ReceiptEffectPartial, contract.ReceiptEffectUnknown:
			return 3
		case contract.ReceiptEffectFailed, contract.ReceiptEffectMixedTerminal:
			code = 2
		}
		if stateCode == 3 {
			return 3
		}
		if stateCode == 2 {
			code = 2
		}
	}
	if r.Result.Outcome == core.AdmissionRefused && r.Generated == nil {
		return 2
	}
	if len(r.Diagnostics) != 0 {
		for _, row := range r.Diagnostics {
			if row.Outcome == contract.DiagnosticUnable {
				return 3
			}
		}
		return 2
	}
	return code
}

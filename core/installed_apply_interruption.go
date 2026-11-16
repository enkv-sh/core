package core

import (
	"context"

	"enkv.sh/core/contract"
)

// The result producer retains the actual stage and selection facts. Observing
// interruption at normal return records that separate fact without changing them.
func appendApplyInterruptionDiagnostic(ctx context.Context, out *PublicApplyResult) {
	if ctx == nil || out == nil {
		return
	}
	var reason contract.DiagnosticReason
	switch ctx.Err() {
	case context.Canceled:
		reason = contract.ReasonCancelled
	case context.DeadlineExceeded:
		reason = contract.ReasonExpired
	default:
		return
	}
	for _, row := range out.Diagnostics {
		if row.Subject.Kind == contract.SubjectObservation && row.Outcome == contract.DiagnosticUnable && row.Reason == reason && len(row.Path) == 1 && row.Path[0] == contract.FieldPresence {
			return
		}
	}
	out.Diagnostics = append(out.Diagnostics, contract.Diagnostic{Subject: contract.DiagnosticSubject{Kind: contract.SubjectObservation}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: reason})
}

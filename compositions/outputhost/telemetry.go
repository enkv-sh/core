package outputhost

import (
	"context"
	"errors"
	"os/exec"

	protocol "enkv.sh/sdk/protocols/output"
	"enkv.sh/telemetry"
)

// Output diagnostics use only closed local dispositions and validated result
// classes. Raw child, credential, transport, and provider errors are excluded.
func finishOutputCall(call *telemetry.Call, err error, result *protocol.Result) {
	if err != nil {
		var disposition telemetry.Result
		var reason telemetry.DiagnosticReason
		switch {
		case errors.Is(err, errStagingCleanup):
			disposition, reason = telemetry.ResultEvidenceUnavailable, telemetry.DiagnosticReasonEvidenceUnavailable
		case errors.Is(err, context.Canceled):
			disposition, reason = telemetry.ResultCancelled, telemetry.DiagnosticReasonCancelled
		case errors.Is(err, context.DeadlineExceeded):
			disposition, reason = telemetry.ResultExpired, telemetry.DiagnosticReasonCancelled
		case errors.Is(err, ErrProcess):
			disposition, reason = telemetry.ResultEvidenceUnavailable, telemetry.DiagnosticReasonEvidenceUnavailable
		case errors.Is(err, ErrAdmission), errors.Is(err, ErrPassiveRefused):
			disposition, reason = telemetry.ResultAdmissionRefused, telemetry.DiagnosticReasonAdmissionRefused
		case errors.Is(err, ErrCredential):
			disposition, reason = telemetry.ResultDenied, telemetry.DiagnosticReasonDenied
		case errors.Is(err, protocol.ErrCapacity):
			disposition, reason = telemetry.ResultCapacityExceeded, telemetry.DiagnosticReasonCapacityExceeded
		case errors.Is(err, protocol.ErrProtocol):
			disposition, reason = telemetry.ResultInvalid, telemetry.DiagnosticReasonInvalidFormat
		default:
			disposition, reason = telemetry.ResultEvidenceUnavailable, telemetry.DiagnosticReasonEvidenceUnavailable
		}
		call.ReturnDetails((telemetry.DiagnosticDetails{}).WithErrorFacts(reason, 0))
		call.Finish(disposition)
		return
	}
	if result == nil {
		call.Finish(telemetry.ResultSuccess)
		return
	}
	switch result.Class {
	case protocol.ClassAcknowledged:
		call.Finish(telemetry.ResultSuccess)
	case protocol.ClassQualifiedNoEffect:
		call.Finish(telemetry.ResultUnchanged)
	default:
		call.ReturnDetails((telemetry.DiagnosticDetails{}).WithErrorFacts(telemetry.DiagnosticReasonUncertain, 0))
		call.Finish(telemetry.ResultUnknown)
	}
}

// A completed Wait confirms that the child was reaped. It does not by itself
// prove successful child completion: a canceled child normally exits nonzero.
func finishOutputJoin(call *telemetry.Call, waitErr, contextErr error, cancelSignalAccepted bool) {
	if waitErr == nil {
		call.Finish(telemetry.ResultSuccess)
		return
	}
	var exit *exec.ExitError
	if errors.As(waitErr, &exit) {
		if cancelSignalAccepted && contextErr != nil {
			result := telemetry.ResultCancelled
			if errors.Is(contextErr, context.DeadlineExceeded) {
				result = telemetry.ResultExpired
			}
			call.ReturnDetails((telemetry.DiagnosticDetails{}).WithErrorFacts(telemetry.DiagnosticReasonCancelled, 0))
			call.Finish(result)
			return
		}
		call.ReturnDetails((telemetry.DiagnosticDetails{}).WithErrorFacts(telemetry.DiagnosticReasonUncertain, 0))
		call.Finish(telemetry.ResultFailure)
		return
	}
	call.ReturnDetails((telemetry.DiagnosticDetails{}).WithErrorFacts(telemetry.DiagnosticReasonEvidenceUnavailable, 0))
	call.Finish(telemetry.ResultEvidenceUnavailable)
}

package manifesthost

import (
	"context"
	"errors"

	manifest "enkv.sh/sdk/manifest-generator"
	"enkv.sh/telemetry"
)

func finishCall(call *telemetry.Call, err error) {
	if err == nil {
		call.Finish(telemetry.ResultSuccess)
		return
	}
	result, reason := telemetry.ResultInvalid, telemetry.DiagnosticReasonInvalidFormat
	switch {
	case errors.Is(err, context.Canceled):
		result, reason = telemetry.ResultCancelled, telemetry.DiagnosticReasonCancelled
	case errors.Is(err, context.DeadlineExceeded):
		result, reason = telemetry.ResultExpired, telemetry.DiagnosticReasonCancelled
	case errors.Is(err, ErrAdmission), errors.Is(err, ErrUnsupported):
		result, reason = telemetry.ResultAdmissionRefused, telemetry.DiagnosticReasonAdmissionRefused
	case errors.Is(err, ErrProcess):
		result, reason = telemetry.ResultEvidenceUnavailable, telemetry.DiagnosticReasonEvidenceUnavailable
	}
	call.ReturnDetails((telemetry.DiagnosticDetails{}).WithErrorFacts(reason, 0))
	call.Finish(result)
}

func finishRender(call *telemetry.Call, err error, failure manifest.Failure) {
	if err != nil {
		finishCall(call, err)
		return
	}
	if failure == "" {
		call.Finish(telemetry.ResultSuccess)
		return
	}
	result, reason := telemetry.ResultInvalid, telemetry.DiagnosticReasonInvalidFormat
	switch failure {
	case manifest.Cancelled:
		result, reason = telemetry.ResultCancelled, telemetry.DiagnosticReasonCancelled
	case manifest.Expired:
		result, reason = telemetry.ResultExpired, telemetry.DiagnosticReasonCancelled
	case manifest.LimitExceeded:
		result, reason = telemetry.ResultCapacityExceeded, telemetry.DiagnosticReasonCapacityExceeded
	}
	call.ReturnDetails((telemetry.DiagnosticDetails{}).WithErrorFacts(reason, 0))
	call.Finish(result)
}

package plugininstallation

import (
	"context"
	"errors"

	"enkv.sh/telemetry"
)

const (
	opResolve  = telemetry.OpPluginResolve
	opCapture  = telemetry.OpPluginCapture
	opAcquire  = telemetry.OpPluginAcquire
	opSelect   = telemetry.OpPluginSelect
	opRetained = telemetry.OpPluginRetained
)

func startCall(ctx context.Context, operation telemetry.Operation) (context.Context, *telemetry.Call) {
	call := telemetry.Start(ctx, telemetry.ProviderApplication, operation)
	call.Checkpoint(telemetry.DiagnosticAdmission, telemetry.DiagnosticReasonNone)
	return telemetry.CallContext(ctx, call), call
}

func finishCall(call *telemetry.Call, err error) {
	result := telemetry.ResultSuccess
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		result = telemetry.ResultCancelled
	case errors.Is(err, ErrIdentity), errors.Is(err, ErrInvalid), errors.Is(err, ErrSignature):
		result = telemetry.ResultIntegrityFailure
	case candidateMaySkip(err) || onlyIncompatible(err):
		result = telemetry.ResultAdmissionRefused
	case errors.Is(err, ErrMissing):
		result = telemetry.ResultReadMissing
	case err != nil:
		result = telemetry.ResultFailure
	}
	call.Finish(result)
}

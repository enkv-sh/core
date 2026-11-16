package compositionfull

import (
	"context"
	"errors"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core/contract"
	enkvcrypto "enkv.sh/crypto"
	"enkv.sh/telemetry"
)

// TelemetryResult reports the local operation's established terminal class.
// Result delivery has a separate owner.
func (r *PrepareResult) TelemetryResult(err error) telemetry.Result {
	if r == nil || !r.valid() {
		return telemetry.ResultFailure
	}
	cancelled := errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
	for _, diagnostic := range r.facts.Diagnostics {
		cancelled = cancelled || diagnostic.Reason == "cancelled"
	}
	switch {
	case r.facts.Outcome == "unknown":
		return telemetry.ResultWriteUnknown
	case cancelled:
		return telemetry.ResultCancelled
	case PrepareExitCode(r, nil) == 3:
		return telemetry.ResultEvidenceUnavailable
	case r.facts.Outcome == "refused":
		return telemetry.ResultWriteRefused
	case r.SetupRequired():
		return telemetry.ResultSetupIncomplete
	case r.facts.Outcome != "complete":
		return telemetry.ResultFailure
	default:
		return telemetry.ResultSuccess
	}
}

func (r *SetResult) TelemetryResult(err error) telemetry.Result {
	if r == nil {
		return telemetry.ResultFailure
	}
	var unknown *configuration.UnknownEdit
	var input *enkvcrypto.ConfigurationInputError
	cancelled := errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.As(err, &input) && (input.Code == contract.CryptoCancelled || input.Code == contract.CryptoExpired)
	switch {
	case errors.As(err, &unknown):
		return telemetry.ResultWriteUnknown
	case r.StateResult == SetSuccess:
		if err != nil {
			return telemetry.ResultFailure
		}
		return telemetry.ResultSuccess
	case errors.Is(err, configuration.ErrEditBounds):
		return telemetry.ResultCapacityExceeded
	case cancelled:
		return telemetry.ResultCancelled
	case err != nil:
		return telemetry.ResultWriteRefused
	default:
		return telemetry.ResultAdmissionRefused
	}
}

func (r *LocalEditResult) TelemetryResult(err error) telemetry.Result {
	if r == nil {
		return telemetry.ResultFailure
	}
	switch {
	case r.outcome == "pending" || r.outcome == "unknown":
		return telemetry.ResultWriteUnknown
	case errors.Is(err, configuration.ErrEditBounds):
		return telemetry.ResultCapacityExceeded
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return telemetry.ResultCancelled
	case err != nil && r.outcome == "edited":
		return telemetry.ResultFailure
	case err != nil:
		return telemetry.ResultWriteRefused
	case r.outcome != "edited":
		return telemetry.ResultAdmissionRefused
	default:
		return telemetry.ResultSuccess
	}
}

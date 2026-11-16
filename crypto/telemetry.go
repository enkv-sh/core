package crypto

import (
	"context"
	"encoding/hex"

	"enkv.sh/compositions/generatorhost"
	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

// Metrics observe returned operations. They receive no packet, secret length,
// resource identity, admission identifier or provider error text.
func (r *Runtime) Exchange(ctx context.Context, q contract.CryptoRequest) contract.CryptoResponse {
	return exchangeWithTelemetry(ctx, q, r.exchange)
}

func (r *Runtime) exchangeWithApplyOwner(ctx context.Context, q contract.CryptoRequest, expected *applyAdmission) contract.CryptoResponse {
	return exchangeWithTelemetry(ctx, q, func(ctx context.Context, q contract.CryptoRequest) contract.CryptoResponse {
		return r.applyExchangeOwned(ctx, q, expected)
	})
}

func (r *Runtime) exchangeWithInitOwner(ctx context.Context, q contract.CryptoRequest, expected *initAdmission) contract.CryptoResponse {
	return exchangeWithTelemetry(ctx, q, func(ctx context.Context, q contract.CryptoRequest) contract.CryptoResponse {
		return r.qualifyInit(ctx, q, expected)
	})
}

func exchangeWithTelemetry(ctx context.Context, q contract.CryptoRequest, exchange func(context.Context, contract.CryptoRequest) contract.CryptoResponse) contract.CryptoResponse {
	call := telemetry.Start(ctx, telemetry.ProviderCrypto, cryptoOperation(q.Kind))
	ctx = telemetry.CallContext(ctx, call)
	call.Checkpoint(telemetry.DiagnosticPrivateCustody, telemetry.DiagnosticReasonNone)
	reply := exchange(ctx, q)
	finishCryptoCall(call, reply.ResultCode)
	return reply
}

func (r *Runtime) sealInput(ctx context.Context, id contract.ID) ([]byte, contract.CryptoResultCode) {
	call := telemetry.Start(ctx, telemetry.ProviderCrypto, telemetry.OpCryptoSealSource)
	ctx = telemetry.CallContext(ctx, call)
	call.Checkpoint(telemetry.DiagnosticPrivateCustody, telemetry.DiagnosticReasonNone)
	body, code := r.sealInputEnvelope(ctx, id)
	finishCryptoCall(call, code)
	return body, code
}

func (r *Runtime) consume(ctx context.Context, id contract.ID) consumerResult {
	call := telemetry.Start(ctx, telemetry.ProviderCrypto, telemetry.OpCryptoConsume)
	ctx = telemetry.CallContext(ctx, call)
	call.Checkpoint(telemetry.DiagnosticPrivateCustody, telemetry.DiagnosticReasonNone)
	result := r.consumeSelected(ctx, id)
	finishCryptoCall(call, result.code)
	return result
}

func (r *Runtime) invokeGeneratedProducer(ctx context.Context, id, locator, authority contract.ID) generatedProducerOutput {
	call := telemetry.Start(ctx, telemetry.ProviderCrypto, telemetry.OpCryptoGeneratedProducerEntry)
	ctx = telemetry.CallContext(ctx, call)
	call.Checkpoint(telemetry.DiagnosticPrivateCustody, telemetry.DiagnosticReasonNone)
	out := r.invokeGeneratedProducerOwned(ctx, id, locator, authority)
	finishCryptoCall(call, out.code)
	return out
}

func invokeGeneratedProcess(ctx context.Context, launcher generatorhost.Launcher, command contract.GeneratedProducerCommand, intent []byte) (generatedProducerReturn, contract.CryptoResultCode) {
	call := telemetry.StartWithDetails(ctx, telemetry.ProviderCrypto, telemetry.OpCryptoGeneratedProcess,
		generatedAttemptDetails(command.AttemptID))
	ctx = telemetry.CallContext(ctx, call)
	out, code := invokeGeneratedProcessOwned(ctx, launcher, command, intent)
	if code != contract.CryptoSuccess || out.Facts.Disposition != contract.GeneratorDispositionOwnedUnusableCreate && out.Facts.Disposition != contract.GeneratorDispositionUnknown {
		finishCryptoCall(call, code)
		return out, code
	}
	// These are decoded process observations. The producer owner still checks
	// their admitted lifecycle, resource, request and intent before accepting the result.
	class, disposition := telemetry.DiagnosticReasonInvalid, "owned unusable create"
	if out.Facts.Disposition == contract.GeneratorDispositionUnknown {
		class, disposition = telemetry.DiagnosticReasonUncertain, "unknown"
	}
	var reason string
	switch out.Facts.Reason {
	case contract.GeneratorReasonMissingValue:
		reason = "missing value"
	case contract.GeneratorReasonInvalidValue:
		reason = "invalid value"
	case contract.GeneratorReasonControls:
		reason = "controls"
	case contract.GeneratorReasonInactive:
		reason = "inactive"
	case contract.GeneratorReasonMalformed:
		reason = "malformed"
	case contract.GeneratorReasonOverflow:
		reason = "overflow"
	case contract.GeneratorReasonRejected:
		reason = "rejected"
	case contract.GeneratorReasonTransport:
		reason = "transport"
	case contract.GeneratorReasonDeadline:
		reason = "deadline"
	case contract.GeneratorReasonIdentityConflict:
		reason = "identity conflict"
	default:
		finishCryptoCall(call, code)
		return out, code
	}
	call.ReturnDetails((telemetry.DiagnosticDetails{}).WithErrorFacts(class, 0).
		WithReviewedErrorText("generator result: " + disposition + "; reason: " + reason))
	call.FinishReason(cryptoResult(code), class)
	return out, code
}

func generatedAttemptDetails(id contract.ID) telemetry.DiagnosticDetails {
	if id.IsZero() {
		return telemetry.DiagnosticDetails{}
	}
	return (telemetry.DiagnosticDetails{}).WithAttemptID(hex.EncodeToString(id[:]))
}

func finishCryptoCall(call *telemetry.Call, code contract.CryptoResultCode) {
	if code != contract.CryptoSuccess {
		class := telemetry.DiagnosticReasonEvidenceUnavailable
		switch code {
		case contract.CryptoInvalidInput:
			class = telemetry.DiagnosticReasonInvalidFormat
		case contract.CryptoInvalidAdmission:
			class = telemetry.DiagnosticReasonAdmissionRefused
		case contract.CryptoExpired, contract.CryptoCancelled:
			class = telemetry.DiagnosticReasonCancelled
		case contract.CryptoAlreadyUsed:
			class = telemetry.DiagnosticReasonAlreadyUsed
		case contract.CryptoSourceAuthenticationFailed, contract.CryptoStoredAuthenticationFailed:
			class = telemetry.DiagnosticReasonIntegrityFailure
		case contract.CryptoPrivateRouteUnavailable, contract.CryptoCustodyUnavailable:
			class = telemetry.DiagnosticReasonCustodyUnavailable
		case contract.CryptoCapacityExceeded:
			class = telemetry.DiagnosticReasonCapacityExceeded
		}
		call.ReturnDetails((telemetry.DiagnosticDetails{}).WithErrorFacts(class, 0))
	}
	call.Finish(cryptoResult(code))
}

func cryptoOperation(kind contract.CryptoKind) telemetry.Operation {
	switch kind {
	case contract.CryptoCompare:
		return telemetry.OpCryptoCompare
	case contract.CryptoPrepare:
		return telemetry.OpCryptoPrepare
	case contract.CryptoFreeze:
		return telemetry.OpCryptoFreeze
	case contract.CryptoClaim:
		return telemetry.OpCryptoClaim
	case contract.CryptoDiscard:
		return telemetry.OpCryptoDiscard
	case contract.CryptoAccessReplace:
		return telemetry.OpCryptoAccessReplace
	case contract.CryptoQualifyInitKeys:
		return telemetry.OpCryptoQualifyInitKeys
	default:
		return telemetry.OpCryptoExchange
	}
}

func cryptoResult(code contract.CryptoResultCode) telemetry.Result {
	switch code {
	case contract.CryptoSuccess:
		return telemetry.ResultSuccess
	case contract.CryptoInvalidInput:
		return telemetry.ResultInvalid
	case contract.CryptoInvalidAdmission:
		return telemetry.ResultAdmissionRefused
	case contract.CryptoExpired:
		return telemetry.ResultExpired
	case contract.CryptoCancelled:
		return telemetry.ResultCancelled
	case contract.CryptoAlreadyUsed:
		return telemetry.ResultAlreadyUsed
	case contract.CryptoSourceAuthenticationFailed, contract.CryptoStoredAuthenticationFailed:
		return telemetry.ResultIntegrityFailure
	case contract.CryptoPrivateRouteUnavailable, contract.CryptoCustodyUnavailable:
		return telemetry.ResultEvidenceUnavailable
	case contract.CryptoCapacityExceeded:
		return telemetry.ResultCapacityExceeded
	default:
		return telemetry.ResultUnknown
	}
}

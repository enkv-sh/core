package awsprovider

import (
	"context"
	"net/http"
	"strings"

	"enkv.sh/core/contract"
	enkvcrypto "enkv.sh/crypto"
	"enkv.sh/providers/aws/credentials"
	"enkv.sh/telemetry"
)

type telemetryOperationKey struct{}

func startTelemetry(ctx context.Context, operation telemetry.Operation) (context.Context, *telemetry.Call) {
	return startTelemetryDetails(ctx, operation, telemetry.DiagnosticDetails{})
}

func startTelemetryDetails(ctx context.Context, operation telemetry.Operation, details telemetry.DiagnosticDetails) (context.Context, *telemetry.Call) {
	if operation == telemetry.OpAuthentication {
		return credentials.StartAuthenticationTelemetry(ctx)
	}
	call := telemetry.StartWithDetails(ctx, telemetry.ProviderAWS, operation, details)
	if call == nil {
		return ctx, nil
	}
	call.Checkpoint(telemetry.DiagnosticProviderCall, telemetry.DiagnosticReasonNone)
	return context.WithValue(call.Context(), telemetryOperationKey{}, operation), call
}

func storeDetails(s *Store, key string) telemetry.DiagnosticDetails {
	if s == nil || keyLimit(s.config.Prefix, s.config.Domain, key) == 0 {
		return telemetry.DiagnosticDetails{}
	}
	kind := "state_object"
	if key == s.descriptor.HeadKey {
		kind = "state_head"
	}
	return (telemetry.DiagnosticDetails{}).WithPathKind(kind).WithReviewedPath(strings.TrimPrefix(key, s.config.Prefix+"/"))
}

func headStoreDetails(s *Store) telemetry.DiagnosticDetails {
	if s == nil {
		return telemetry.DiagnosticDetails{}
	}
	return storeDetails(s, s.descriptor.HeadKey)
}

func providerReasonDetails(reason contract.Reason) telemetry.DiagnosticDetails {
	class := telemetry.DiagnosticReasonInvalid
	switch reason {
	case contract.ReasonAccess:
		class = telemetry.DiagnosticReasonDenied
	case contract.ReasonTransport:
		class = telemetry.DiagnosticReasonEvidenceUnavailable
	case contract.ReasonMalformed:
		class = telemetry.DiagnosticReasonInvalidFormat
	case contract.ReasonCondition:
		class = telemetry.DiagnosticReasonStalePrecondition
	case contract.ReasonConstruction:
		class = telemetry.DiagnosticReasonConstructionMismatch
	case contract.ReasonLimit:
		class = telemetry.DiagnosticReasonCapacityExceeded
	case contract.ReasonProof:
		class = telemetry.DiagnosticReasonInvalidProof
	}
	return (telemetry.DiagnosticDetails{}).WithErrorFacts(class, 0)
}

func finishReadTelemetry(call *telemetry.Call, result contract.ReadResult) {
	if call == nil {
		return
	}
	if result.Reason != contract.ReasonNone {
		call.ReturnDetails(providerReasonDetails(result.Reason))
	}
	call.OutputBytes(int64(len(result.Body)))
	status := telemetry.ResultUnknown
	switch result.Status {
	case contract.ReadOK:
		status = telemetry.ResultReadOK
	case contract.ReadMissing:
		status = telemetry.ResultReadMissing
	case contract.ReadUnavailable:
		status = telemetry.ResultReadUnavailable
	case contract.ReadInvalid:
		status = telemetry.ResultReadInvalid
	}
	call.Finish(status)
}

func finishImmutableWriteTelemetry(call *telemetry.Call, result contract.WriteResult) {
	if result.Status == contract.WritePrecondition {
		call.ReturnDetails(providerReasonDetails(result.Reason))
		call.Finish(telemetry.ResultVerificationPending)
		return
	}
	finishWriteTelemetry(call, result)
}

func finishWriteTelemetry(call *telemetry.Call, result contract.WriteResult) {
	if call == nil {
		return
	}
	if result.Reason != contract.ReasonNone {
		call.ReturnDetails(providerReasonDetails(result.Reason))
	}
	status := telemetry.ResultUnknown
	switch result.Status {
	case contract.WriteAcknowledged:
		status = telemetry.ResultWriteAcknowledged
	case contract.WritePrecondition:
		status = telemetry.ResultWritePrecondition
	case contract.WriteConflict:
		status = telemetry.ResultWriteConflict
	case contract.WriteUnknown:
		status = telemetry.ResultWriteUnknown
	case contract.WriteRefused:
		status = telemetry.ResultWriteRefused
	}
	call.Finish(status)
}

func finishSignTelemetry(call *telemetry.Call, result contract.SignResult) {
	if call == nil {
		return
	}
	if result.Reason != contract.ReasonNone {
		call.ReturnDetails(providerReasonDetails(result.Reason))
	}
	call.OutputBytes(int64(len(result.Signature)))
	status := telemetry.ResultSignOK
	if result.Reason == contract.ReasonProof {
		status = telemetry.ResultSignInvalid
	} else if result.Reason != contract.ReasonNone {
		status = telemetry.ResultSignUnavailable
	}
	call.Finish(status)
}

func finishQualificationTelemetry(ctx context.Context, call *telemetry.Call, result contract.SigningQualificationResult) {
	if call == nil {
		return
	}
	if ctx.Err() != nil {
		call.ReturnDetails((telemetry.DiagnosticDetails{}).WithErrorFacts(telemetry.DiagnosticReasonCancelled, 0))
		call.Finish(telemetry.ResultCancelled)
		return
	}
	if result.Reason == contract.ReasonLimit {
		call.ReturnDetails((telemetry.DiagnosticDetails{}).WithErrorFacts(telemetry.DiagnosticReasonEvidenceUnavailable, 0))
	} else if result.Reason != contract.ReasonNone {
		call.ReturnDetails(providerReasonDetails(result.Reason))
	}
	status := telemetry.ResultUnknown
	switch result.Reason {
	case contract.ReasonNone:
		if result.Qualified == 1 {
			status = telemetry.ResultSuccess
		} else {
			status = telemetry.ResultInvalid
		}
	case contract.ReasonAccess, contract.ReasonTransport, contract.ReasonLimit:
		status = telemetry.ResultEvidenceUnavailable
	case contract.ReasonMalformed, contract.ReasonCondition, contract.ReasonConstruction, contract.ReasonProof:
		status = telemetry.ResultInvalid
	}
	call.Finish(status)
}

func finishCredentialTelemetry(call *telemetry.Call, ok bool) {
	result := telemetry.ResultFailure
	if ok {
		result = telemetry.ResultSuccess
	}
	call.Finish(result)
}

type httpTelemetry struct {
	attempt           *telemetry.HTTPAttempt
	request, response *telemetry.BodyObservation
	status            int
}

func startHTTPTelemetry(r *http.Request) *httpTelemetry {
	operation, ok := r.Context().Value(telemetryOperationKey{}).(telemetry.Operation)
	if !ok {
		return nil
	}
	attempt := telemetry.StartHTTP(r.Context(), telemetry.ProviderAWS, operation)
	if attempt == nil {
		return nil
	}
	observation := &httpTelemetry{attempt: attempt}
	if r.Body != nil && r.Body != http.NoBody {
		length := r.ContentLength
		if length == 0 {
			length = -1
		}
		observation.request = telemetry.TrackBody(r.Body, length)
		r.Body = observation.request
	}
	return observation
}

func (observation *httpTelemetry) observeResponse(resp *http.Response) {
	if observation == nil || resp == nil {
		return
	}
	observation.status = resp.StatusCode
	if resp.Body != nil {
		observation.response = telemetry.TrackBody(resp.Body, resp.ContentLength)
		resp.Body = observation.response
	}
}

func (observation *httpTelemetry) finish(failed bool) {
	if observation == nil {
		return
	}
	observation.attempt.ObserveRequest(observation.request.Snapshot())
	if observation.response != nil {
		observation.attempt.ObserveResponse(observation.response.Snapshot())
	}
	observation.attempt.Finish(observation.status, failed)
}

// Key telemetry uses only the final bounded status. Packet and key-use evidence
// remain with the operation owner; HTTP metrics count physical attempts.
func finishKeyTelemetry(call *telemetry.Call, status enkvcrypto.KeyStatus) {
	result := telemetry.ResultUnknown
	switch status {
	case enkvcrypto.KeyOK:
		result = telemetry.ResultSuccess
	case enkvcrypto.KeyDenied:
		result = telemetry.ResultDenied
	case enkvcrypto.KeyInvalid, enkvcrypto.KeyAuthenticationFailed:
		result = telemetry.ResultInvalid
	case enkvcrypto.KeyUnavailable:
		result = telemetry.ResultEvidenceUnavailable
	case enkvcrypto.KeyCancelled:
		result = telemetry.ResultCancelled
	}
	call.Finish(result)
}

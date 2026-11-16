package core

import (
	"context"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

// ReadRecipientRegistry authenticates public state without private key use or
// mutation. The caller owns a successful registry after this call returns.
func (e *ReaderEngine) ReadRecipientRegistry(ctx context.Context, requestID contract.ID) PublicRecipientRegistryResult {
	call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreReaderRecipients)
	call.Checkpoint(telemetry.DiagnosticAdmission, telemetry.DiagnosticReasonNone)
	r := e.readRecipientRegistry(telemetry.CallContext(ctx, call), requestID, call)
	finishReaderCall(call, r.StateResult, r.FailureReason)
	return r
}

// Compare borrows stable desired backing until capture. Its result owns safe
// public changes, diagnostics, scope and observation. Private values are absent.
func (e *ReaderEngine) Compare(ctx context.Context, requestID contract.ID, input contract.PublicConfiguration, options ...contract.ComparisonOptions) PublicComparisonResult {
	call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreReaderCompare)
	call.Checkpoint(telemetry.DiagnosticAdmission, telemetry.DiagnosticReasonNone)
	r := e.comparePublic(telemetry.CallContext(ctx, call), requestID, input, call, options...)
	if call == nil {
		return r
	}
	reason := contract.DiagnosticReason("")
	if !r.DiagnosticsComplete {
		reason = contract.ReasonDiagnosticsIncomplete
	} else {
		for _, d := range r.Diagnostics {
			if d.Outcome == contract.DiagnosticUnable && comparisonState([]contract.Diagnostic{d}, true) == r.StateResult {
				reason = d.Reason
				break
			}
		}
	}
	finishReaderCall(call, r.StateResult, reason)
	return r
}

// Manifest borrows stable request backing until its bounded capture. A caller
// must not mutate that backing during capture. Success transfers one complete
// artifact to the caller; its custody determines later correspondence.
func (e *ReaderEngine) Manifest(ctx context.Context, requestID contract.ID, input contract.ManifestRequest) PublicManifestResult {
	call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreReaderManifest)
	call.Checkpoint(telemetry.DiagnosticAdmission, telemetry.DiagnosticReasonNone)
	r := e.manifest(telemetry.CallContext(ctx, call), requestID, input, call)
	if r.StateResult == contract.ReaderSuccess {
		call.OutputBytes(int64(len(r.Artifact)))
		call.ManifestEntries(len(r.Payload.IncludedEntries)+len(r.Payload.ExcludedEntries), len(r.Payload.IncludedEntries), len(r.Payload.ExcludedEntries))
	}
	finishReaderCall(call, r.StateResult, r.FailureReason)
	return r
}

func finishReaderCall(call *telemetry.Call, state contract.ReaderStateResult, reason contract.DiagnosticReason) {
	result := telemetry.ResultAdmissionRefused
	switch state {
	case contract.ReaderSuccess:
		result = telemetry.ResultSuccess
	case contract.ReaderPositiveDefect:
		result = telemetry.ResultIntegrityFailure
	case contract.ReaderUnavailable:
		result = telemetry.ResultEvidenceUnavailable
	case contract.ReaderContention:
		result = telemetry.ResultContention
	case contract.ReaderProfileBlocked:
		result = telemetry.ResultInvalid
	}
	if reason == contract.ReasonCancelled {
		result = telemetry.ResultCancelled
	}
	if reason == contract.ReasonExpired {
		result = telemetry.ResultExpired
	}
	call.FinishReason(result, telemetry.DiagnosticReason(reason))
}

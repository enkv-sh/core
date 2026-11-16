package core

import (
	"context"
	"crypto/sha256"
	"errors"
	"reflect"

	"enkv.sh/core/contract"
	manifest "enkv.sh/sdk/manifest-generator"
	"enkv.sh/telemetry"
)

// PublicManifestResult keeps native issuer context separate from the target.
// Artifact is one caller-owned complete artifact backing; failures return no bytes
// and no success payload. Observation can survive a later local failure.
type PublicManifestResult struct {
	PreAdmission      *PreAdmissionRequestIdentity
	RequestScope      *contract.ManifestRequestScope
	Result            Result
	Context           ReaderOperationContext
	StateResult       contract.ReaderStateResult
	TargetRecipientID contract.ID
	Observation       *manifest.Observation
	FailureReason     contract.DiagnosticReason
	Payload           *contract.ManifestPayload
	Artifact          []byte
}

func (e *ReaderEngine) manifest(ctx context.Context, requestID contract.ID, input contract.ManifestRequest, call *telemetry.Call) PublicManifestResult {
	r := PublicManifestResult{Result: refused(AdmissionInvalid), Context: ReaderOperationContext{Operation: contract.ReaderManifestOperation, RequestID: requestID}, StateResult: contract.ReaderRefused}
	var prepare func(context.Context, contract.ManifestRendererSelection) (manifest.Renderer, manifest.Failure)
	if e != nil {
		e.mu.Lock()
		prepare = e.prepareManifestRenderer
		r.Context.ExpectedDomain = e.expectedDomain
		e.mu.Unlock()
	}
	fail := func(f readerFailure) PublicManifestResult { r.finishManifestFailure(f); return r }
	if e == nil || requestID.IsZero() {
		return fail(readerRefusal(contract.ReasonInvalidInput))
	}
	if f := manifestContextFailure(ctx); f.Outcome != 0 {
		return fail(f)
	}
	owned, err := contract.OwnManifestRequest(input)
	if err != nil {
		var invalid contract.ManifestRequestError
		if errors.As(err, &invalid) {
			return fail(manifestInputFailure(invalid.Reason))
		}
		return fail(manifestInputFailure(contract.ReasonInvalidInput))
	}
	r.RequestScope = &contract.ManifestRequestScope{Renderer: owned.Renderer, FormatContractID: owned.FormatContractID, ConfigContractID: owned.ConfigContractID, Settings: owned.Settings, Selection: manifest.Selection{TargetMode: owned.TargetMode, EntryMode: owned.EntryMode}, ServiceFilter: owned.ServiceFilter}
	request := manifestRequestDigest(requestID, owned)
	inv, f := e.beginReaderInvocation(ctx, contract.ReaderManifestOperation, request)
	if f.Outcome != 0 {
		return fail(f)
	}
	defer inv.Close()

	r.Context.OperationID = readerOperationID(inv.admission, contract.ID{}, contract.ID{})
	if prepare == nil {
		return fail(manifestSDKFailure(manifest.InvalidInput))
	}
	renderer, preparation := prepare(ctx, owned.Renderer)
	if !preparation.Valid() || preparation == "" && renderer == nil || preparation != "" && renderer != nil {
		return fail(manifestSDKFailure(manifest.InvalidResult))
	}
	if preparation != "" {
		return fail(manifestSDKFailure(preparation))
	}
	if reason := inv.admission.failure(ctx, contract.ReaderManifestOperation, request); reason != "" {
		return fail(readerRefusal(reason))
	}
	call.Checkpoint(telemetry.DiagnosticStateLoading, telemetry.DiagnosticReasonNone)
	selected, f := inv.loadPublicSelection(ctx, contract.ReaderManifestOperation, request, nil)
	if f.Outcome != 0 {
		return fail(f)
	}
	r.Observation = &manifest.Observation{DomainID: manifest.ID(selected.image.root.Domain), HEADRevisionID: manifest.ID(selected.basis.anchor.head.Core.Revision), SnapshotID: manifest.ID(selected.image.root.Snapshot)}
	r.Context.OperationID = readerOperationID(inv.admission, contract.ID(r.Observation.HEADRevisionID), contract.ID(r.Observation.SnapshotID))
	r.TargetRecipientID, f = manifestTargetRecipient(selected, owned)
	if f.Outcome != 0 {
		return fail(f)
	}
	call.Checkpoint(telemetry.DiagnosticAuthentication, telemetry.DiagnosticReasonNone)
	projection, f := buildOwnedManifestSelection(ctx, selected, owned)
	if f.Outcome != 0 {
		return fail(f)
	}
	defer releaseManifestProjection(projection)
	artifact, metadata, f := renderManifestArtifact(ctx, projection, renderer)
	if f.Outcome != 0 {
		return fail(f)
	}
	// Completion authenticates the original invocation, never a later HEAD.
	if reason := inv.admission.failure(ctx, contract.ReaderManifestOperation, request); reason != "" {
		clear(artifact[:cap(artifact)])
		return fail(readerRefusal(reason))
	}
	included := make([]manifest.EntryIdentity, len(projection.Entries))
	for i, row := range projection.Entries {
		included[i] = manifest.EntryIdentity{Name: row.Name, EntryIncarnationID: row.EntryIncarnationID}
	}
	r.Payload = &contract.ManifestPayload{Observation: *r.Observation, TargetRecipientID: contract.ID(projection.TargetRecipientID), Selection: projection.Selection, ServiceFilter: projection.ServiceFilter, IncludedEntries: included, ExcludedEntries: projection.ExcludedEntries, Renderer: owned.Renderer, FormatContractID: projection.FormatContractID, ConfigContractID: projection.ConfigContractID, Settings: projection.Settings, ArtifactLength: metadata.Length, ArtifactDigest: contract.ID(metadata.Digest), EvidenceLimit: manifest.EvidenceLimit}
	r.Artifact = artifact
	r.StateResult = contract.ReaderSuccess
	r.Result = Result{Outcome: ObservedCurrent, ObservedRevision: contract.ID(r.Observation.HEADRevisionID), ObservedSnapshotID: contract.ID(r.Observation.SnapshotID), Evidence: AuthenticatedClosure}
	return r
}

func manifestRequestDigest(requestID contract.ID, request contract.ManifestRequest) contract.ID {
	h := sha256.New()
	h.Write([]byte("ENKV/consumption-manifest-request/v3\x00"))
	h.Write(requestID[:])
	hashPublicSemantic(h, reflect.ValueOf(request))
	return contract.ID(h.Sum(nil))
}

// Manifest has one failure; comparison vector precedence does not apply.
func (r *PublicManifestResult) finishManifestFailure(f readerFailure) {
	r.Artifact, r.Payload = nil, nil
	r.FailureReason, r.Result = f.diagnostic, f.Result
	r.StateResult = readerFailureState(f.diagnostic)
}

func releaseManifestProjection(m *manifest.Projection) {
	for i := range m.Entries {
		clear(m.Entries[i].PlainValue[:cap(m.Entries[i].PlainValue)])
		m.Entries[i] = manifest.Entry{}
	}
	m.Entries, m.ExcludedEntries, m.ResolvedEntries = nil, nil, nil
}

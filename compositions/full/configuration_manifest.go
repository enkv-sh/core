package compositionfull

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"enkv.sh/compositions/configuration"
	"enkv.sh/compositions/full/plugininstallation"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	"enkv.sh/sdk/artifact"
	manifest "enkv.sh/sdk/manifest-generator"
	"enkv.sh/telemetry"
)

// These sentinels support errors.Is for source capture/check and close
// failures. Source disposal and artifact issuance are separate result facts.
var (
	ErrManifestSource      = errors.New("manifest source capture or verification failed")
	ErrManifestSourceClose = errors.New("manifest source close failed")
)

// ManifestOptions selects an already trusted installed renderer. Settings are
// author input; the selected build normalizes them before Core admission.
// Calls copy mutable options before source capture. ExactNames requires a
// nonnil EntryNames slice (an empty slice selects none); AllAuthorized requires
// nil. ServiceFilter, when present, is one exact semantic service identity.
type ManifestOptions struct {
	Plugin                   string
	Settings                 []byte
	TargetMode               manifest.TargetMode
	EntryMode                manifest.EntryMode
	TargetRecipientID        contract.ID
	TargetRecipientReference string
	EntryNames               []string
	ServiceFilter            *string
}

func ownManifestOptions(input ManifestOptions) (ManifestOptions, error) {
	fail := func(reason contract.DiagnosticReason) (ManifestOptions, error) {
		return ManifestOptions{}, contract.ManifestRequestError{Reason: reason}
	}
	if !artifact.ValidPluginID(input.Plugin) {
		return fail(contract.ReasonInvalidInput)
	}
	if failure := manifest.ValidateSettings(input.Settings); failure != "" {
		switch failure {
		case manifest.LimitExceeded:
			return fail(contract.ReasonLimitExceeded)
		case manifest.InvalidUTF8:
			return fail(contract.ReasonInvalidUTF8)
		default:
			return fail(contract.ReasonInvalidInput)
		}
	}
	if !(manifest.Selection{TargetMode: input.TargetMode, EntryMode: input.EntryMode}).Valid() || input.TargetMode == manifest.CurrentAuthority && !input.TargetRecipientID.IsZero() || input.TargetMode == manifest.ExactRecipient && input.TargetRecipientID.IsZero() && input.TargetRecipientReference == "" || input.EntryMode == manifest.AllAuthorized && input.EntryNames != nil || input.EntryMode == manifest.ExactNames && input.EntryNames == nil {
		return fail(contract.ReasonInvalidInput)
	}
	if !(RecipientSelector{Reference: input.TargetRecipientReference, ID: input.TargetRecipientID}).valid() || input.TargetMode == manifest.CurrentAuthority && input.TargetRecipientReference != "" {
		return fail(contract.ReasonInvalidInput)
	}
	if len(input.EntryNames) > manifest.MaxEntries {
		return fail(contract.ReasonLimitExceeded)
	}
	for _, name := range input.EntryNames {
		if len(name) > manifest.MaxNameBytes {
			return fail(contract.ReasonLimitExceeded)
		}
		if !utf8.ValidString(name) {
			return fail(contract.ReasonInvalidUTF8)
		}
	}
	if input.ServiceFilter != nil {
		if len(*input.ServiceFilter) > manifest.MaxContractBytes {
			return fail(contract.ReasonLimitExceeded)
		}
		if *input.ServiceFilter == "" || !utf8.ValidString(*input.ServiceFilter) {
			return fail(contract.ReasonInvalidInput)
		}
	}
	owned := input
	owned.Plugin = strings.Clone(input.Plugin)
	owned.TargetRecipientReference = strings.Clone(input.TargetRecipientReference)
	owned.Settings = bytes.Clone(input.Settings)
	owned.EntryNames = slices.Clone(input.EntryNames)
	for i, name := range owned.EntryNames {
		owned.EntryNames[i] = strings.Clone(name)
	}
	slices.Sort(owned.EntryNames)
	for i := 1; i < len(owned.EntryNames); i++ {
		if owned.EntryNames[i] == owned.EntryNames[i-1] {
			return fail(contract.ReasonDuplicateEntry)
		}
	}
	if input.ServiceFilter != nil {
		value := strings.Clone(*input.ServiceFilter)
		owned.ServiceFilter = &value
	}
	return owned, nil
}

type manifestReaderOpener func(context.Context, ReaderConfig) (*core.ReaderEngine, error)

type manifestSourceError struct{ cause error }

func (e *manifestSourceError) Error() string { return ErrManifestSource.Error() }
func (e *manifestSourceError) Unwrap() error { return errors.Join(ErrManifestSource, e.cause) }

type manifestRendererCapture func(context.Context, *configuration.Pair, plugininstallation.Requirement, ManifestOptions) (contract.ManifestRequest, func(context.Context, contract.ManifestRendererSelection) (manifest.Renderer, manifest.Failure), error)

// NewManifestRefusal creates correlated invalid-input facts without source access.
func NewManifestRefusal(format configuration.Format) (core.PublicManifestResult, error) {
	return newConfigurationManifestResult(contract.ID{}, format)
}

func newConfigurationManifestResult(nonce contract.ID, format configuration.Format) (core.PublicManifestResult, error) {
	id, q, err := configurationPreAdmission(format, nonce)
	return core.PublicManifestResult{Context: core.ReaderOperationContext{Operation: contract.ReaderManifestOperation, RequestID: nonce, OperationID: id},
		PreAdmission: q, StateResult: contract.ReaderRefused, FailureReason: contract.ReasonInvalidInput,
		Result: core.Result{Outcome: core.AdmissionRefused, Reason: core.AdmissionInvalid}}, err
}

func manifestConfigurationFailure(ctx context.Context, out core.PublicManifestResult, stage string, err error, unavailable bool) core.PublicManifestResult {
	var input *configurationQueryInputError
	if errors.As(err, &input) {
		stage = input.stage
	}
	reason := contract.DiagnosticReason(configurationFailureCode(ctx, err))
	var request contract.ManifestRequestError
	if errors.As(err, &request) {
		reason = request.Reason
	}
	out.StateResult, out.FailureReason = contract.ReaderRefused, reason
	out.Result = core.Result{Outcome: core.AdmissionRefused, Reason: core.AdmissionInvalid}
	if reason == contract.ReasonUnsupportedProfile || reason == contract.ReasonUnsupportedSchema {
		out.StateResult = contract.ReaderProfileBlocked
	}
	if unavailable && (ctx == nil || ctx.Err() == nil) {
		out.StateResult, out.FailureReason = contract.ReaderUnavailable, contract.ReasonEvidenceUnavailable
		out.Result = core.Result{Outcome: core.EvidenceUnavailable, Reason: core.ReadUnavailable}
	}
	if out.PreAdmission != nil {
		out.PreAdmission.Stage, out.PreAdmission.Code = stage, string(out.FailureReason)
	}
	return out
}

func captureConfigurationManifestRequest(ctx context.Context, nonce contract.ID, input ManifestOptions, out *core.PublicManifestResult) (ManifestOptions, error) {
	owned, err := ownManifestOptions(input)
	if err != nil {
		*out = manifestConfigurationFailure(ctx, *out, "declaration", err, false)
		return ManifestOptions{}, err
	}
	if ctx == nil || ctx.Err() != nil || nonce.IsZero() {
		*out = manifestConfigurationFailure(ctx, *out, "context", contract.ErrRecord, false)
		return ManifestOptions{}, contract.ErrRecord
	}
	deadline, finite := ctx.Deadline()
	if !finite {
		*out = manifestConfigurationFailure(ctx, *out, "context", contract.ErrRecord, false)
		return ManifestOptions{}, contract.ErrRecord
	}
	if !time.Now().Before(deadline) {
		*out = manifestConfigurationFailure(ctx, *out, "context", context.DeadlineExceeded, false)
		return ManifestOptions{}, contract.ErrRecord
	}
	return owned, nil
}

// IssueConfigurationManifest borrows the trusted source pair until return.
// Success transfers one complete artifact. A later source verification failure
// is returned separately and does not revoke completed issuance.
func IssueConfigurationManifest(ctx context.Context, nonce contract.ID, pair *configuration.Pair, request ManifestOptions) (core.PublicManifestResult, error) {
	return issueConfigurationManifest(ctx, nonce, pair, request, NewDefaultReader, configurationCaptureManifest)
}

func issueConfigurationManifest(ctx context.Context, nonce contract.ID, pair *configuration.Pair, request ManifestOptions, open manifestReaderOpener, capture manifestRendererCapture) (core.PublicManifestResult, error) {
	var format configuration.Format
	if pair != nil {
		format = pair.Format
	}
	out, err := newConfigurationManifestResult(nonce, format)
	if err != nil {
		return out, ErrManifestSource
	}
	owned, err := captureConfigurationManifestRequest(ctx, nonce, request, &out)
	if err != nil {
		return out, nil
	}
	return issueConfigurationManifestWithIdentity(ctx, nonce, pair, owned, open, capture, out)
}

func issueConfigurationManifestWithIdentity(ctx context.Context, nonce contract.ID, pair *configuration.Pair, owned ManifestOptions, open manifestReaderOpener, capture manifestRendererCapture, initial core.PublicManifestResult) (core.PublicManifestResult, error) {
	if open == nil || capture == nil {
		return manifestConfigurationFailure(ctx, initial, "construction", contract.ErrRecord, false), nil
	}
	c, _, model, err := configurationPublicQueryModel(ctx, nonce, pair)
	if err != nil {
		return manifestConfigurationFailure(ctx, initial, "declaration", err, false), &manifestSourceError{cause: err}
	}
	if owned.TargetMode == manifest.ExactRecipient {
		owned.TargetRecipientID, err = (RecipientSelector{Reference: owned.TargetRecipientReference, ID: owned.TargetRecipientID}).resolve(model)
		if err != nil {
			return manifestConfigurationFailure(ctx, initial, "declaration", err, false), nil
		}
		owned.TargetRecipientReference = ""
	}
	request, prepare, err := capture(ctx, pair, configurationPluginRequirement(model, owned.Plugin), owned)
	owned = ManifestOptions{}
	if err != nil {
		var refused contract.ManifestRequestError
		unavailable := !errors.As(err, &refused)
		failure := manifestConfigurationFailure(ctx, initial, "construction", err, unavailable)
		if pair.CheckUnchanged(ctx) != nil {
			return failure, ErrManifestSource
		}
		return failure, nil
	}
	c.PrepareManifestRenderer = prepare
	initial.RequestScope = &contract.ManifestRequestScope{Renderer: request.Renderer, FormatContractID: request.FormatContractID, ConfigContractID: request.ConfigContractID, Settings: request.Settings, Selection: manifest.Selection{TargetMode: request.TargetMode, EntryMode: request.EntryMode}, ServiceFilter: request.ServiceFilter}
	initial.Context.ExpectedDomain, _ = capacityReaderScope(c)
	reader, err := open(ctx, c)
	if err != nil || reader == nil {
		if reader != nil {
			reader.Close()
		}
		return manifestConfigurationFailure(ctx, initial, "construction", err, true), nil
	}
	releaseConfigurationReader(&c)
	sourceFailed := false
	out := func() core.PublicManifestResult {
		defer reader.Close()
		if err := pair.CheckUnchanged(ctx); err != nil {
			sourceFailed = true
			return manifestConfigurationFailure(ctx, initial, "capture", err, false)
		}
		result := reader.Manifest(ctx, nonce, request)
		if result.Context.OperationID.IsZero() {
			result.Context.OperationID, result.PreAdmission = initial.Context.OperationID, initial.PreAdmission
			result.PreAdmission.Stage, result.PreAdmission.Code = "observation", string(result.FailureReason)
		}
		return result
	}()
	if err := pair.CheckUnchanged(ctx); err != nil {
		sourceFailed = true
	}
	if sourceFailed {
		return out, ErrManifestSource
	}
	return out, nil
}

// IssueConfigurationManifestFile owns its captured source pair. Source cleanup
// errors remain separate from completed issuance and its transferred artifact.
func IssueConfigurationManifestFile(ctx context.Context, nonce contract.ID, path string, format configuration.Format, request ManifestOptions) (core.PublicManifestResult, error) {
	return issueConfigurationManifestFile(ctx, nonce, path, format, request, NewDefaultReader, configurationCaptureManifest, (*configuration.Pair).Close)
}

func issueConfigurationManifestFile(ctx context.Context, nonce contract.ID, path string, format configuration.Format, request ManifestOptions, open manifestReaderOpener, capture manifestRendererCapture, closePair func(*configuration.Pair) error) (out core.PublicManifestResult, err error) {
	out, err = newConfigurationManifestResult(nonce, format)
	if err != nil {
		return out, ErrManifestSource
	}
	owned, requestErr := captureConfigurationManifestRequest(ctx, nonce, request, &out)
	if requestErr != nil {
		return out, nil
	}
	pair, captureErr := configuration.Capture(ctx, path, format)
	if captureErr != nil {
		return manifestConfigurationFailure(ctx, out, "capture", captureErr, false), &manifestSourceError{cause: captureErr}
	}
	defer func() {
		if closePair(pair) != nil {
			err = errors.Join(err, ErrManifestSourceClose)
		}
	}()
	return issueConfigurationManifestWithIdentity(ctx, nonce, pair, owned, open, capture, out)
}

// WriteConfigurationManifest borrows the pair through native settlement and
// returns issuance and file facts without retaining artifact bytes.
func WriteConfigurationManifest(ctx context.Context, nonce contract.ID, pair *configuration.Pair, request ManifestOptions, outPath string) ManifestFileResult {
	return writeConfigurationManifest(ctx, nonce, pair, request, outPath, NewDefaultReader, configurationCaptureManifest)
}

func writeConfigurationManifest(ctx context.Context, nonce contract.ID, pair *configuration.Pair, request ManifestOptions, outPath string, open manifestReaderOpener, capture manifestRendererCapture) ManifestFileResult {
	issuance, err := issueConfigurationManifest(ctx, nonce, pair, request, open, capture)
	return deliverConfigurationManifest(ctx, issuance, err, pair, outPath)
}

func deliverConfigurationManifest(ctx context.Context, issuance core.PublicManifestResult, sourceErr error, pair *configuration.Pair, path string) (out ManifestFileResult) {
	defer func() {
		if sourceErr != nil {
			out.SourceCleanup = ManifestSourceUnknown
		}
	}()
	if issuance.StateResult != contract.ReaderSuccess {
		out = NewManifestFileResult(issuance)
		out.SourceFailure = configurationSourceFailure("source", sourceErr)
		out.SourceCleanup = ManifestSourceComplete
		return out
	}
	target, delivery := newManifestFileTarget(path, []string{pair.Editable.OriginalPath(), pair.Generated.OriginalPath()}, pair.CheckUnchanged)
	if sourceErr != nil && delivery.Failure == nil {
		reason := ManifestIOFailure
		if errors.Is(ctx.Err(), context.Canceled) {
			reason = ManifestCanceled
		} else if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			reason = ManifestDeadlineExceeded
		}
		delivery.Failure = &ManifestFileFailure{Stage: ManifestPreflightStage, Reason: reason}
		target = nil
	}
	return installConfigurationManifest(ctx, issuance, target, delivery)
}

func installConfigurationManifest(ctx context.Context, issuance core.PublicManifestResult, target *manifestFileTarget, delivery ManifestDelivery) (out ManifestFileResult) {
	out = NewManifestFileResult(issuance)
	out.SourceCleanup = ManifestSourceComplete
	defer func() {
		clear(out.Issuance.Artifact)
		out.Issuance.Artifact = nil
	}()
	call := telemetry.Start(ctx, telemetry.ProviderApplication, telemetry.OpManifestFileWrite)
	call.Checkpoint(telemetry.DiagnosticAdmission, telemetry.DiagnosticReasonNone)
	if target != nil {
		if checkSource := target.checkSource; checkSource != nil {
			target.checkSource = func(ctx context.Context) error {
				err := checkSource(ctx)
				if err != nil {
					out.SourceCleanup = ManifestSourceUnknown
				}
				return err
			}
			defer func() { target.checkSource = checkSource }()
		}
		delivery = target.install(telemetry.CallContext(ctx, call), ManifestArtifact{RendererArtifactID: out.Issuance.Payload.Renderer.ArtifactID, FormatContractID: out.Issuance.Payload.FormatContractID}, out.Issuance.Artifact, call)
	}
	if p := out.Issuance.Payload; p != nil {
		delivery.Artifact = &ManifestArtifact{RendererArtifactID: p.Renderer.ArtifactID, FormatContractID: p.FormatContractID, Length: p.ArtifactLength, Digest: p.ArtifactDigest}
	}
	out.Delivery = delivery
	result, reason := telemetry.ResultFailure, telemetry.DiagnosticReasonNone
	if delivery.NativeCompletion == ManifestNativeComplete {
		result = telemetry.ResultSuccess
		call.OutputBytes(int64(len(out.Issuance.Artifact)))
	} else if delivery.Failure != nil {
		reason = telemetry.DiagnosticReasonEvidenceUnavailable
		switch delivery.Failure.Reason {
		case ManifestCanceled:
			result, reason = telemetry.ResultCancelled, telemetry.DiagnosticReasonCancelled
		case ManifestDeadlineExceeded:
			result, reason = telemetry.ResultExpired, telemetry.DiagnosticReasonCancelled
		case ManifestInvalidTarget, ManifestSourceAlias, ManifestReservedPath:
			result, reason = telemetry.ResultAdmissionRefused, telemetry.DiagnosticReasonAdmissionRefused
		}
	}
	call.FinishReason(result, reason)
	return out
}

// WriteConfigurationManifestFile owns the captured pair through delivery and
// reports source cleanup independently from issuance and native completion.
func WriteConfigurationManifestFile(ctx context.Context, nonce contract.ID, path string, format configuration.Format, request ManifestOptions, outPath string) ManifestFileResult {
	return writeConfigurationManifestFile(ctx, nonce, path, format, request, outPath, NewDefaultReader, configurationCaptureManifest, (*configuration.Pair).Close)
}

func writeConfigurationManifestFile(ctx context.Context, nonce contract.ID, path string, format configuration.Format, request ManifestOptions, outPath string, open manifestReaderOpener, capture manifestRendererCapture, closePair func(*configuration.Pair) error) (out ManifestFileResult) {
	issuance, err := newConfigurationManifestResult(nonce, format)
	out = NewManifestFileResult(issuance)
	out.SourceCleanup = ManifestSourceComplete
	if err != nil {
		return out
	}
	owned, err := captureConfigurationManifestRequest(ctx, nonce, request, &issuance)
	if err != nil {
		out.Issuance = issuance
		return out
	}
	pair, err := configuration.Capture(ctx, path, format)
	if err != nil {
		out.Issuance = manifestConfigurationFailure(ctx, issuance, "capture", err, false)
		out.SourceFailure = configurationSourceFailure("source", err)
		out.SourceCleanup = ManifestSourceUnknown
		return out
	}
	defer func() {
		if closePair(pair) != nil {
			out.SourceCleanup = ManifestSourceFailed
		}
	}()
	issuance, err = issueConfigurationManifestWithIdentity(ctx, nonce, pair, owned, open, capture, issuance)
	return deliverConfigurationManifest(ctx, issuance, err, pair, outPath)
}

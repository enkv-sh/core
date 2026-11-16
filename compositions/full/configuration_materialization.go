package compositionfull

import (
	"context"
	"crypto/rand"
	"errors"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	"enkv.sh/crypto"
)

var (
	ErrMaterializationSource      = errors.New("materialization source capture failed")
	ErrMaterializationSourceClose = errors.New("materialization source close failed")
)

type materializationOpener func(context.Context, MaterializationConfig) (*core.InstalledMaterialization, error)

// NewMaterializationRefusal retains recognized-operation correlation before source access.
func NewMaterializationRefusal(format configuration.Format) (core.MaterializationResult, error) {
	return newConfigurationMaterializationResult(contract.ID{}, format)
}

func newConfigurationMaterializationResult(nonce contract.ID, format configuration.Format) (core.MaterializationResult, error) {
	id, q, err := configurationPreAdmission(format, nonce)
	return core.MaterializationResult{Operation: contract.MaterializationOperation, RequestID: nonce, OperationID: id, PreAdmission: q,
		StateResult: contract.MaterializationRefused, Result: core.Result{Outcome: core.AdmissionRefused, Reason: core.AdmissionInvalid},
		Failure: &contract.MaterializationFailure{Stage: contract.MaterializationAdmissionStage, Reason: contract.MaterializationInvalidRequest}}, err
}

// MaterializeConfiguration borrows the complete source pair until private and native work joins.
// Current values and Recipient bindings come only from authenticated Store state.
func MaterializeConfiguration(ctx context.Context, request contract.MaterializationRequest, pair *configuration.Pair, outPath string) ConfigurationMaterializationResult {
	return materializeConfiguration(ctx, request, pair, outPath, NewDefaultMaterialization)
}

func materializeConfiguration(ctx context.Context, request contract.MaterializationRequest, pair *configuration.Pair, outPath string, open materializationOpener) ConfigurationMaterializationResult {
	var format configuration.Format
	if pair != nil {
		format = pair.Format
	}
	raw, err := newConfigurationMaterializationResult(request.RequestNonce, format)
	initial := ConfigurationMaterializationResult{MaterializationResult: raw}
	if err != nil {
		return initial
	}
	return materializeConfigurationWithIdentity(ctx, request, pair, outPath, open, initial, RecipientSelector{ID: request.RecipientID})
}

func materializationConfigurationFailure(ctx context.Context, out ConfigurationMaterializationResult, stage string, err error, state contract.MaterializationStateResult, reason contract.MaterializationFailureReason) ConfigurationMaterializationResult {
	var input *configurationQueryInputError
	if errors.As(err, &input) {
		stage = input.stage
	}
	code := configurationFailureCode(ctx, err)
	if ctx != nil && ctx.Err() != nil {
		if errors.Is(ctx.Err(), context.Canceled) {
			state, reason = contract.MaterializationUnavailable, contract.MaterializationCanceled
		} else {
			state, reason = contract.MaterializationRefused, contract.MaterializationDeadlineExceeded
		}
	}
	out.StateResult = state
	out.Failure = &contract.MaterializationFailure{Stage: contract.MaterializationAdmissionStage, Reason: reason}
	out.Result = core.Result{Outcome: core.AdmissionRefused, Reason: core.AdmissionInvalid}
	if state == contract.MaterializationUnavailable {
		out.Result = core.Result{Outcome: core.EvidenceUnavailable, Reason: core.CustodyUnavailable}
		if ctx == nil || ctx.Err() == nil {
			code = string(contract.ReasonEvidenceUnavailable)
		}
	}
	if out.PreAdmission != nil {
		out.PreAdmission.Stage, out.PreAdmission.Code = stage, code
	}
	if f := configurationSourceFailure("source", err); validConfigurationAdmissionSourceFailure(f, out.PreAdmission, out.RequestIdentity, out.Result) {
		out.SourceFailure = f
	}
	return out
}

func materializeConfigurationWithIdentity(ctx context.Context, request contract.MaterializationRequest, pair *configuration.Pair, outPath string, open materializationOpener, initial ConfigurationMaterializationResult, selector RecipientSelector) ConfigurationMaterializationResult {
	owned, err := contract.OwnMaterializationRequest(request)
	if err != nil || open == nil || !selector.valid() || !request.RecipientID.IsZero() && request.RecipientID != selector.ID {
		return materializationConfigurationFailure(ctx, initial, "declaration", err, contract.MaterializationRefused, contract.MaterializationInvalidRequest)
	}
	c, pins, model, err := configurationPublicQueryModel(ctx, owned.RequestNonce, pair)
	if err != nil {
		return materializationConfigurationFailure(ctx, initial, "declaration", err, contract.MaterializationRefused, contract.MaterializationInvalidRequest)
	}
	owned.RecipientID, err = selector.resolve(model)
	if err != nil {
		return materializationConfigurationFailure(ctx, initial, "declaration", err, contract.MaterializationRefused, contract.MaterializationInvalidRequest)
	}
	var surface contract.ID
	if _, err := rand.Read(surface[:]); err != nil || surface.IsZero() {
		return materializationConfigurationFailure(ctx, initial, "construction", nil, contract.MaterializationUnavailable, contract.MaterializationIOFailure)
	}
	target, err := crypto.NewMaterializationFileTarget(contract.MaterializationTarget{Path: outPath, SurfaceID: surface, Format: contract.MaterializationDotenvFormat, NativeProfile: contract.MaterializationNativeFileProfile}, []string{pair.Editable.OriginalPath(), pair.Generated.OriginalPath()})
	if err != nil {
		state, reason := contract.MaterializationRefused, contract.MaterializationInvalidTarget
		if errors.Is(err, crypto.ErrMaterializationProfile) {
			state, reason = contract.MaterializationProfileBlocked, contract.MaterializationProfileUnqualified
		}
		if errors.Is(err, crypto.ErrMaterializationFileIO) {
			state, reason = contract.MaterializationUnavailable, contract.MaterializationIOFailure
		}
		return materializationConfigurationFailure(ctx, initial, "output", err, state, reason)
	}
	engine, err := open(ctx, MaterializationConfig{ReaderConfig: c, SourcePins: pins, CheckSource: pair.CheckUnchanged, Target: target})
	if err != nil || engine == nil {
		if engine != nil {
			engine.Close()
		}
		return materializationConfigurationFailure(ctx, initial, "construction", err, contract.MaterializationUnavailable, contract.MaterializationRequiredReadUnavailable)
	}
	releaseConfigurationReader(&c)
	defer engine.Close()
	out := ConfigurationMaterializationResult{MaterializationResult: engine.Materialize(ctx, owned)}
	if out.RequestIdentity.IsZero() {
		out.OperationID, out.PreAdmission = initial.OperationID, initial.PreAdmission
		out.PreAdmission.Stage, out.PreAdmission.Code = "observation", string(contract.ReasonInvalidInput)
		if out.StateResult == contract.MaterializationUnavailable {
			out.PreAdmission.Code = string(contract.ReasonEvidenceUnavailable)
		}
	}
	return out
}

// MaterializeConfigurationFile owns the captured pair. A source close failure is
// returned separately; it never changes completed native facts or repeats delivery.
func MaterializeConfigurationFile(ctx context.Context, request contract.MaterializationRequest, path string, format configuration.Format, outPath string) (out ConfigurationMaterializationResult, err error) {
	return materializeConfigurationFile(ctx, request, path, format, outPath, NewDefaultMaterialization, (*configuration.Pair).Close)
}

// MaterializeConfigurationRecipientFile resolves a CLI selector from the same
// captured pair used for consumption. Exact IDs need no local declaration.
func MaterializeConfigurationRecipientFile(ctx context.Context, request contract.MaterializationRequest, path string, format configuration.Format, outPath string, selector RecipientSelector) (ConfigurationMaterializationResult, error) {
	return materializeConfigurationSelectedFile(ctx, request, path, format, outPath, NewDefaultMaterialization, (*configuration.Pair).Close, selector)
}

func materializeConfigurationFile(ctx context.Context, request contract.MaterializationRequest, path string, format configuration.Format, outPath string, open materializationOpener, closePair func(*configuration.Pair) error) (ConfigurationMaterializationResult, error) {
	return materializeConfigurationSelectedFile(ctx, request, path, format, outPath, open, closePair, RecipientSelector{ID: request.RecipientID})
}

func materializeConfigurationSelectedFile(ctx context.Context, request contract.MaterializationRequest, path string, format configuration.Format, outPath string, open materializationOpener, closePair func(*configuration.Pair) error, selector RecipientSelector) (out ConfigurationMaterializationResult, err error) {
	raw, identityErr := newConfigurationMaterializationResult(request.RequestNonce, format)
	out, err = ConfigurationMaterializationResult{MaterializationResult: raw}, identityErr
	if err != nil {
		return out, ErrMaterializationSource
	}
	owned, requestErr := contract.OwnMaterializationRequest(request)
	if requestErr != nil {
		return materializationConfigurationFailure(ctx, out, "declaration", requestErr, contract.MaterializationRefused, contract.MaterializationInvalidRequest), nil
	}
	if ctx == nil || ctx.Err() != nil {
		return materializationConfigurationFailure(ctx, out, "context", nil, contract.MaterializationRefused, contract.MaterializationInvalidRequest), nil
	}
	deadline, finite := ctx.Deadline()
	if !finite {
		return materializationConfigurationFailure(ctx, out, "context", nil, contract.MaterializationRefused, contract.MaterializationInvalidRequest), nil
	}
	if !time.Now().Before(deadline) {
		return materializationConfigurationFailure(ctx, out, "context", context.DeadlineExceeded, contract.MaterializationRefused, contract.MaterializationDeadlineExceeded), nil
	}
	pair, captureErr := configuration.Capture(ctx, path, format)
	if captureErr != nil {
		return materializationConfigurationFailure(ctx, out, "capture", captureErr, contract.MaterializationRefused, contract.MaterializationInvalidRequest), ErrMaterializationSource
	}
	defer func() {
		if closePair(pair) != nil {
			err = ErrMaterializationSourceClose
		}
	}()
	out = materializeConfigurationWithIdentity(ctx, owned, pair, outPath, open, out, selector)
	return out, nil
}

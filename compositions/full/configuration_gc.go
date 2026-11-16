package compositionfull

import (
	"context"
	"path/filepath"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// GCApplyRequest chooses exactly one fresh artifact or selected operation.
type GCApplyRequest struct {
	RequestNonce contract.ID
	PlanPath     string
	OperationID  contract.ID
}

type GCApplyDelivery struct {
	CleanupFailed bool `json:"cleanup_failed"`
}
type GCApplyResult struct {
	SourceFailure *ConfigurationSourceFailure
	Operation     core.PublicGCResult
	Delivery      GCApplyDelivery
	PreAdmission  *core.PreAdmissionRequestIdentity
}

func NewGCApplyRefusal(format configuration.Format) (GCApplyResult, error) {
	return newConfigurationGCApplyResult(contract.ID{}, format)
}

func newConfigurationGCApplyResult(nonce contract.ID, format configuration.Format) (GCApplyResult, error) {
	id, q, err := configurationPreAdmission(format, nonce)
	out := GCApplyResult{Operation: core.PublicGCResult{Operation: core.GCApplyOperation, RequestID: nonce, OperationID: id, Result: core.Result{Outcome: core.AdmissionRefused, Reason: core.AdmissionInvalid}, StateResult: "refused"}, PreAdmission: q}
	if err != nil {
		return out, err
	}
	if format != 0 && format != configuration.JSON && format != configuration.YAML {
		return out, ErrGCPlan
	}
	return out, nil
}

func ApplyConfigurationGC(ctx context.Context, request GCApplyRequest, pair *configuration.Pair) GCApplyResult {
	return applyConfigurationGC(ctx, request, pair, NewDefaultCapacityReader, defaultGCMutationResources)
}

func applyConfigurationGC(ctx context.Context, request GCApplyRequest, pair *configuration.Pair,
	open func(context.Context, CapacityReaderConfig) (*core.InstalledCapacityReader, error),
	mutation func(context.Context, *configuration.Model, abandonmentSource) (core.GCMutationResources, error)) (out GCApplyResult) {
	var format configuration.Format
	if pair != nil {
		format = pair.Format
	}
	out, err := newConfigurationGCApplyResult(request.RequestNonce, format)
	if err != nil {
		return out
	}
	return applyConfigurationGCWithIdentity(ctx, request, pair, open, mutation, out)
}

func configurationGCApplyFailure(ctx context.Context, out GCApplyResult, stage string, err error) GCApplyResult {
	if out.PreAdmission != nil {
		out.PreAdmission.Stage, out.PreAdmission.Code = stage, configurationFailureCode(ctx, err)
	}
	if f := configurationSourceFailure("source", err); f != nil && validConfigurationAdmissionSourceFailure(f, out.PreAdmission, out.Operation.RequestIdentity, out.Operation.Result) {
		out.SourceFailure = f
	}
	return out
}

func applyConfigurationGCWithIdentity(ctx context.Context, request GCApplyRequest, pair *configuration.Pair,
	open func(context.Context, CapacityReaderConfig) (*core.InstalledCapacityReader, error),
	mutation func(context.Context, *configuration.Model, abandonmentSource) (core.GCMutationResources, error), initial GCApplyResult) (out GCApplyResult) {
	out = initial
	if ctx == nil || ctx.Err() != nil || request.RequestNonce.IsZero() || open == nil || mutation == nil {
		return configurationGCApplyFailure(ctx, out, "context", nil)
	}
	if (request.PlanPath == "") == request.OperationID.IsZero() {
		return configurationGCApplyFailure(ctx, out, "declaration", nil)
	}
	if deadline, ok := ctx.Deadline(); !ok || !time.Now().Before(deadline) {
		return configurationGCApplyFailure(ctx, out, "context", context.DeadlineExceeded)
	}
	model, err := configuration.Parse(ctx, pair)
	if err != nil {
		return configurationGCApplyFailure(ctx, out, "parse", err)
	}
	source, err := abandonmentSourceFacts(pair, model)
	if err != nil {
		return configurationGCApplyFailure(ctx, out, "declaration", err)
	}
	c, err := configurationReaderConfig(model)
	if err != nil {
		return configurationGCApplyFailure(ctx, out, "declaration", err)
	}
	var encoded []byte
	if request.PlanPath != "" {
		if !filepath.IsAbs(request.PlanPath) || filepath.Clean(request.PlanPath) != request.PlanPath || !gcPlanOutputPath(request.PlanPath, pair) {
			return configurationGCApplyFailure(ctx, out, "declaration", nil)
		}
		// The artifact's syntax and complete source scope are checked before
		// default bucket credentials. The engine owns the sole target preflight.
		encoded, err = readGCPlan(ctx, request.PlanPath, source.domain, source.store, source.basis, source.pins)
		if err != nil {
			return configurationGCApplyFailure(ctx, out, "declaration", err)
		}
		defer clear(encoded)
	}
	if err := pair.CheckUnchanged(ctx); err != nil {
		return configurationGCApplyFailure(ctx, out, "capture", err)
	}
	reader, err := open(ctx, CapacityReaderConfig{ReaderConfig: c, SourcePins: source.pins, CheckSource: pair.CheckUnchanged})
	if err != nil || reader == nil {
		if reader != nil {
			reader.Close()
		}
		out = configurationGCApplyFailure(ctx, out, "construction", err)
		if ctx.Err() == nil {
			out.Operation.Result = core.Result{Outcome: core.EvidenceUnavailable, Reason: core.ReadUnavailable}
			out.Operation.StateResult = "unavailable"
			out.PreAdmission.Code = string(contract.ReasonEvidenceUnavailable)
		}
		return out
	}
	engine, err := core.NewInstalledGC(core.GCInstallation{Reader: reader, CompositionID: CompatibilityManifest().Identity,
		ConstructMutation: func(ctx context.Context) (core.GCMutationResources, error) { return mutation(ctx, model, source) }})
	if err != nil || engine == nil {
		reader.Close()
		return configurationGCApplyFailure(ctx, out, "construction", err)
	}
	// Successful construction transfers reader ownership. Join before the
	// borrowed Pair closes and before the original operation context ends.
	localID, localIdentity := out.Operation.OperationID, out.PreAdmission
	defer func() {
		if engine.Close() != nil {
			out.Delivery.CleanupFailed = true
		}
	}()
	if request.PlanPath != "" {
		out.Operation = engine.ApplyPlan(ctx, core.GCApplyPlanRequest{RequestNonce: request.RequestNonce, EncodedPlan: encoded})
	} else {
		out.Operation = engine.Continue(ctx, core.GCContinueRequest{RequestNonce: request.RequestNonce, OperationID: request.OperationID})
	}
	if out.Operation.RequestIdentity.IsZero() {
		if out.Operation.OperationID.IsZero() {
			out.Operation.OperationID = localID
		}
		out.PreAdmission = localIdentity
		out.PreAdmission.Stage, out.PreAdmission.Code = "observation", string(contract.ReasonEvidenceUnavailable)
		if out.Operation.Result.Outcome == core.AdmissionRefused {
			out.PreAdmission.Code = string(contract.ReasonInvalidInput)
		}
	} else {
		out.PreAdmission = nil
	}
	return out
}

func defaultGCMutationResources(ctx context.Context, model *configuration.Model, source abandonmentSource) (core.GCMutationResources, error) {
	// The existing administrative constructor installs exact Store and Normal
	// Trust only. Its invocation is inside the engine's lazy validated factory.
	r, err := defaultAbandonmentResources(ctx, model, source, true)
	return core.GCMutationResources{Store: r.store, Trust: r.trust, Close: r.close}, err
}

func ApplyConfigurationGCFile(ctx context.Context, request GCApplyRequest, path string, format configuration.Format) (out GCApplyResult) {
	out, err := newConfigurationGCApplyResult(request.RequestNonce, format)
	if err != nil {
		return out
	}
	if request.RequestNonce.IsZero() {
		return configurationGCApplyFailure(ctx, out, "context", nil)
	}
	if (request.PlanPath == "") == request.OperationID.IsZero() {
		return configurationGCApplyFailure(ctx, out, "declaration", nil)
	}
	pair, err := configuration.Capture(ctx, path, format)
	if err != nil {
		return configurationGCApplyFailure(ctx, out, "capture", err)
	}
	defer func() {
		if pair.Close() != nil {
			out.Delivery.CleanupFailed = true
		}
	}()
	out = applyConfigurationGCWithIdentity(ctx, request, pair, NewDefaultCapacityReader, defaultGCMutationResources, out)
	return out
}

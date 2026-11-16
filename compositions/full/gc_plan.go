package compositionfull

import (
	"context"
	"errors"
	"path/filepath"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

var ErrGCPlan = errors.New("GC plan refused")

type GCPlanRequest struct {
	RequestNonce, OperationID contract.ID
	Cursor, ArtifactPath      string
}

type GCPlanDelivery struct {
	PlanCreated   bool `json:"plan_created"`
	PlanSynced    bool `json:"plan_synced"`
	PlanReadback  bool `json:"plan_readback"`
	PlanFailed    bool `json:"plan_failed"`
	CleanupFailed bool `json:"cleanup_failed"`
}

type GCPlanResult struct {
	SourceFailure *ConfigurationSourceFailure
	Operation     core.PublicGCPreviewResult
	Delivery      GCPlanDelivery
}

func NewGCPlanRefusal(format configuration.Format) (GCPlanResult, error) {
	base, err := newConfigurationQueryRefusal(core.GCPlanOperation, contract.ID{}, format)
	return GCPlanResult{Operation: core.PublicGCPreviewResult{PublicQueryResult: base}}, err
}

func PlanConfigurationGC(ctx context.Context, request GCPlanRequest, pair *configuration.Pair) GCPlanResult {
	return planConfigurationGC(ctx, request, pair, NewDefaultCapacityReader, nativeAbandonPlanIO())
}

func planConfigurationGC(ctx context.Context, request GCPlanRequest, pair *configuration.Pair, open func(context.Context, CapacityReaderConfig) (*core.InstalledCapacityReader, error), ops abandonPlanIO) (out GCPlanResult) {
	var format configuration.Format
	if pair != nil {
		format = pair.Format
	}
	base, err := newConfigurationQueryRefusal(core.GCPlanOperation, request.RequestNonce, format)
	out.Operation.PublicQueryResult = base
	if err != nil {
		return out
	}
	return planConfigurationGCWithIdentity(ctx, request, pair, open, ops, base)
}

func planConfigurationGCWithIdentity(ctx context.Context, request GCPlanRequest, pair *configuration.Pair, open func(context.Context, CapacityReaderConfig) (*core.InstalledCapacityReader, error), ops abandonPlanIO, base core.PublicQueryResult) (out GCPlanResult) {
	out.Operation.PublicQueryResult = base
	if open == nil {
		configurationQueryFailure(ctx, &out.Operation.PublicQueryResult, &out.SourceFailure, "construction", nil, false)
		return out
	}
	if request.OperationID.IsZero() || !gcPlanOutputPath(request.ArtifactPath, pair) {
		configurationQueryFailure(ctx, &out.Operation.PublicQueryResult, &out.SourceFailure, "declaration", nil, false)
		return out
	}
	c, pins, err := configurationPublicQueryInput(ctx, request.RequestNonce, pair)
	if err != nil {
		configurationQueryFailure(ctx, &out.Operation.PublicQueryResult, &out.SourceFailure, "declaration", err, false)
		return out
	}
	domain, store := capacityReaderScope(c)
	out.Operation.DomainID = domain
	if _, err := core.DecodeGCCursor(request.Cursor, domain, store); err != nil {
		configurationQueryFailure(ctx, &out.Operation.PublicQueryResult, &out.SourceFailure, "declaration", err, false)
		return out
	}
	reader, err := open(ctx, CapacityReaderConfig{ReaderConfig: c, SourcePins: pins, CheckSource: pair.CheckUnchanged})
	if err != nil || reader == nil {
		if reader != nil {
			reader.Close()
		}
		configurationQueryFailure(ctx, &out.Operation.PublicQueryResult, &out.SourceFailure, "construction", err, true)
		return out
	}
	releaseConfigurationReader(&c)
	defer reader.Close()
	out.Operation = reader.PlanGC(ctx, core.GCPreviewRequest{RequestNonce: request.RequestNonce, OperationID: request.OperationID, Cursor: request.Cursor})
	finishConfigurationQuery(&out.Operation.PublicQueryResult, base)
	if out.Operation.Payload == nil || out.Operation.Result.Outcome != core.ObservedCurrent {
		return out
	}
	if err := out.Operation.Validate(); err != nil {
		out.Delivery.PlanFailed = true
		out.Operation.Payload = nil
		out.Operation.Result = core.Result{Outcome: core.IntegrityFailure, Reason: core.InvalidRelation}
		out.Operation.StateResult = core.PublicQueryPositiveDefect
		out.Operation.FailureReason = contract.ReasonSelectedRelationInvalid
		return out
	}
	if err := pair.CheckUnchanged(ctx); err != nil {
		out.Operation.Payload = nil
		configurationQueryFailure(ctx, &out.Operation.PublicQueryResult, &out.SourceFailure, "capture", err, false)
		return out
	}
	delivery, err := writeGCPlan(ctx, request.ArtifactPath, out.Operation.Payload.EncodedPlan, ops)
	out.Delivery = delivery
	if err != nil {
		out.Delivery.PlanFailed = true
	}
	if err := pair.CheckUnchanged(ctx); err != nil {
		out.Operation.Payload = nil
		out.Delivery.PlanFailed = true
		configurationQueryFailure(ctx, &out.Operation.PublicQueryResult, &out.SourceFailure, "capture", err, false)
	}
	return out
}

func PlanConfigurationGCFile(ctx context.Context, request GCPlanRequest, path string, format configuration.Format) (out GCPlanResult) {
	base, err := newConfigurationQueryRefusal(core.GCPlanOperation, request.RequestNonce, format)
	out.Operation.PublicQueryResult = base
	if err != nil {
		return out
	}
	pair, err := configuration.Capture(ctx, path, format)
	if err != nil {
		configurationQueryFailure(ctx, &out.Operation.PublicQueryResult, &out.SourceFailure, "capture", err, false)
		return out
	}
	defer func() {
		if pair.Close() != nil {
			out.Delivery.CleanupFailed = true
		}
	}()
	out = planConfigurationGCWithIdentity(ctx, request, pair, NewDefaultCapacityReader, nativeAbandonPlanIO(), base)
	return out
}

func gcPlanOutputPath(path string, pair *configuration.Pair) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || pair == nil || pair.Editable == nil || pair.Generated == nil {
		return false
	}
	return path != pair.Editable.OriginalPath() && path != pair.Generated.OriginalPath()
}

func readGCPlan(ctx context.Context, path string, domain contract.ID, store contract.Descriptor, basis core.PublicBasis, pins core.AdministrativeSourcePins) ([]byte, error) {
	body, err := core.ReadLocalProtectedFile(ctx, path, contract.GCPlanMaxLength)
	if err != nil {
		return nil, errors.Join(ErrGCPlan, err)
	}
	plan, err := contract.DecodeGCPlan(body)
	if err != nil || core.ValidateGCPlanScope(plan, domain, store, basis, pins) != nil {
		clear(body)
		return nil, ErrGCPlan
	}
	return body, nil
}

func writeGCPlan(ctx context.Context, path string, body []byte, ops abandonPlanIO) (delivery GCPlanDelivery, err error) {
	call := telemetry.Start(ctx, telemetry.ProviderApplication, telemetry.OpGCPlanWrite)
	call.Checkpoint(telemetry.DiagnosticCandidatePersistence, telemetry.DiagnosticReasonNone)
	call.InputBytes(int64(len(body)))
	if _, decodeErr := contract.DecodeGCPlan(body); decodeErr != nil {
		err = ErrGCPlan
	} else {
		var d AbandonmentDelivery
		d, err = writeProtectedPlanFile(ctx, path, body, contract.GCPlanMaxLength, ops)
		delivery = GCPlanDelivery{PlanCreated: d.PlanCreated, PlanSynced: d.PlanSynced, PlanReadback: d.PlanReadback}
		if err != nil {
			err = errors.Join(ErrGCPlan, err)
		}
	}
	if err == nil {
		call.OutputBytes(int64(len(body)))
		call.Finish(telemetry.ResultSuccess)
	} else if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		call.FinishReason(telemetry.ResultCancelled, telemetry.DiagnosticReasonCancelled)
	} else {
		call.FinishReason(telemetry.ResultFailure, telemetry.DiagnosticReasonInvalidReference)
	}
	return delivery, err
}

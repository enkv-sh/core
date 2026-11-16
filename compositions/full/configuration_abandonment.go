package compositionfull

import (
	"context"
	"errors"
	"net/http"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

type AbandonmentRequest struct {
	Operation                  core.AdministrativeOperation
	TargetGroupID, OperationID contract.ID
	PlanPath, ArtifactPath     string
}
type AbandonmentDelivery struct {
	PlanCreated   bool `json:"plan_created"`
	PlanSynced    bool `json:"plan_synced"`
	PlanReadback  bool `json:"plan_readback"`
	PlanFailed    bool `json:"plan_failed"`
	CleanupFailed bool `json:"cleanup_failed"`
}
type AbandonmentResult struct {
	SourceFailure *ConfigurationSourceFailure
	Operation     core.PublicAdministrativeResult
	Delivery      AbandonmentDelivery
}
type abandonmentResources struct {
	reader core.PublicSelectedReader
	store  contract.Store
	trust  contract.Trust
	close  func() error
}
type abandonmentSource struct {
	domain      contract.ID
	store       contract.Descriptor
	basis       core.PublicBasis
	basisDigest contract.ID
	control     contract.ControlCore
	pins        core.AdministrativeSourcePins
}

func NewAbandonmentRefusal(operation core.AdministrativeOperation, format configuration.Format) (AbandonmentResult, error) {
	return newAbandonmentRefusal(operation, format, contract.ID{})
}
func newAbandonmentRefusal(operation core.AdministrativeOperation, format configuration.Format, nonce contract.ID) (AbandonmentResult, error) {
	switch operation {
	case core.AdministrativeList, core.AdministrativePlan, core.AdministrativeApply, core.AdministrativeReceipt:
	default:
		return AbandonmentResult{}, ErrAbandonmentPlan
	}
	id, q, err := configurationPreAdmission(format, nonce)
	return AbandonmentResult{Operation: core.PublicAdministrativeResult{Operation: operation, OperationID: id, RequestID: nonce, PreAdmission: q, Result: core.Result{Outcome: core.AdmissionRefused, Reason: core.AdmissionInvalid}, StateResult: "refused"}}, err
}

// AbandonConfigurationFile captures one installed source and its generated
// dependency. Source input can name public resources, never implementations.
func AbandonConfigurationFile(ctx context.Context, nonce contract.ID, path string, format configuration.Format, request AbandonmentRequest) AbandonmentResult {
	return abandonConfigurationFile(ctx, nonce, path, format, request, defaultAbandonmentResources, nativeAbandonPlanIO())
}
func abandonConfigurationFile(ctx context.Context, nonce contract.ID, path string, format configuration.Format, request AbandonmentRequest,
	open func(context.Context, *configuration.Model, abandonmentSource, bool) (abandonmentResources, error), planIO abandonPlanIO) (out AbandonmentResult) {
	out, err := newAbandonmentRefusal(request.Operation, format, nonce)
	if err != nil {
		return out
	}
	refuse := func(stage string, err error) {
		out.Operation.PreAdmission.Stage = stage
		out.Operation.PreAdmission.Code = configurationFailureCode(ctx, err)
		if f := configurationSourceFailure("source", err); f != nil && validConfigurationAdmissionSourceFailure(f, out.Operation.PreAdmission, out.Operation.RequestIdentity, out.Operation.Result) {
			out.SourceFailure = f
		}
	}
	if ctx == nil || ctx.Err() != nil || nonce.IsZero() || open == nil {
		refuse("context", nil)
		return out
	}
	if deadline, ok := ctx.Deadline(); !ok || !time.Now().Before(deadline) {
		refuse("context", context.DeadlineExceeded)
		return out
	}
	if request.Operation == core.AdministrativePlan && !(core.AdministrativePlanRequest{TargetGroupID: request.TargetGroupID, ArtifactPath: request.ArtifactPath}).Valid() {
		refuse("declaration", nil)
		return out
	}
	pair, err := configuration.Capture(ctx, path, format)
	if err != nil {
		refuse("capture", err)
		return out
	}
	var session *core.AuthoritySession
	var closeResources func() error
	defer func() {
		var closeErr error
		if session != nil {
			closeErr = session.Close()
		}
		if closeResources != nil {
			closeErr = errors.Join(closeErr, closeResources())
		}
		if err := errors.Join(closeErr, pair.Close()); err != nil {
			out.Delivery.CleanupFailed = true
		}
	}()
	initialOperationID := out.Operation.OperationID
	initialPreAdmission := *out.Operation.PreAdmission
	defer func() {
		if out.Operation.Query == nil && out.Operation.RequestIdentity.IsZero() && out.Operation.PreAdmission == nil {
			identity := initialPreAdmission
			identity.Stage = "observation"
			code := contract.ReasonEvidenceUnavailable
			switch out.Operation.Result.Outcome {
			case core.AdmissionRefused:
				switch out.Operation.Result.Reason {
				case core.StalePrecondition, core.DifferentSelection:
					code = contract.ReasonReadContention
				case core.InvalidRelation:
					code = contract.ReasonSelectedRelationInvalid
				case core.CapacityExceeded:
					code = contract.ReasonLimitExceeded
				default:
					code = contract.ReasonInvalidInput
					if out.Operation.Result.Reason == core.AdmissionInvalid {
						code = contract.DiagnosticReason(configurationFailureCode(ctx, nil))
					}
				}
			case core.IntegrityFailure:
				switch out.Operation.Result.Reason {
				case core.InvalidProof:
					code = contract.ReasonProofInvalid
				case core.InvalidFormat, core.InvalidReference:
					code = contract.ReasonSelectedObjectInvalid
				case core.InvalidRelation:
					code = contract.ReasonSelectedRelationInvalid
				}
			case core.RootLossUnsupported:
				code = contract.ReasonSelectedObjectUnavailable
			case core.Contention:
				code = contract.ReasonReadContention
			}
			identity.Code = string(code)
			out.Operation.PreAdmission = &identity
			out.Operation.OperationID = initialOperationID
		}
	}()
	model, err := configuration.Parse(ctx, pair)
	if err != nil || !model.Resolved {
		refuse("parse", err)
		return out
	}
	installed, err := abandonmentSourceFacts(pair, model)
	if err != nil {
		refuse("public-basis", err)
		return out
	}
	var preview core.EndWorkPreview
	if request.Operation == core.AdministrativeApply {
		preview, err = readAbandonPlan(ctx, request.PlanPath, installed.domain, installed.store, installed.pins, installed.basisDigest)
		if err != nil {
			refuse("declaration", err)
			return out
		}
	}
	if err := pair.CheckUnchanged(ctx); err != nil {
		refuse("capture", err)
		return out
	}
	mutation := request.Operation == core.AdministrativeApply
	resources, err := open(ctx, model, installed, mutation)
	if err != nil {
		if resources.reader != nil {
			resources.reader.Close()
		}
		if resources.close != nil && resources.close() != nil {
			out.Delivery.CleanupFailed = true
		}
		refuse("construction", err)
		return out
	}
	if resources.close == nil {
		resources.close = func() error { return nil }
	}
	if mutation {
		session, err = core.NewInstalledAdministrativeAuthority(core.AdministrativeAuthorityInstallation{ExpectedDomain: installed.domain, ExpectedStore: installed.store, PublicBasis: installed.basis, CompositionID: CompatibilityManifest().Identity, SourcePins: installed.pins, Store: resources.store, Trust: resources.trust, CheckSource: pair.CheckUnchanged, CloseInstalled: resources.close})
	} else {
		session, err = core.NewInstalledAdministrativeReader(core.AdministrativeReadInstallation{ExpectedDomain: installed.domain, ExpectedStore: installed.store, PublicBasis: installed.basis, CompositionID: CompatibilityManifest().Identity, SourcePins: installed.pins, Source: resources.reader, CheckSource: pair.CheckUnchanged}, request.Operation)
	}
	if err != nil || session == nil {
		if resources.reader != nil {
			resources.reader.Close()
		}
		if resources.close() != nil {
			out.Delivery.CleanupFailed = true
		}
		refuse("construction", err)
		return out
	}
	if !mutation {
		closeResources = resources.close
	}
	switch request.Operation {
	case core.AdministrativeList:
		out.Operation = session.List(ctx, nonce)
	case core.AdministrativeReceipt:
		out.Operation = session.Receipt(ctx, nonce, request.OperationID)
	case core.AdministrativeApply:
		out.Operation = session.Apply(ctx, nonce, preview)
	case core.AdministrativePlan:
		out.Operation = session.Plan(ctx, nonce, core.AdministrativePlanRequest{TargetGroupID: request.TargetGroupID, ArtifactPath: request.ArtifactPath})
		if out.Operation.Result.Outcome != core.ObservedCurrent {
			return out
		}
		body, err := encodeAbandonPlan(out.Operation, installed.store, installed.pins, installed.basisDigest)
		if err != nil {
			out.Delivery.PlanFailed = true
			out.Operation.Plan = nil
			out.Operation.Result = core.Result{Outcome: core.IntegrityFailure, Reason: core.InvalidFormat}
			out.Operation.StateResult = "positive-defect"
			return out
		}
		delivery, err := writeAbandonPlan(ctx, request.ArtifactPath, body, planIO)
		out.Delivery = delivery
		if err != nil {
			out.Delivery.PlanFailed = true
			out.Operation.Plan = nil
			out.Operation.Result = core.Result{Outcome: core.EvidenceUnavailable, Reason: core.ReadUnavailable}
			out.Operation.StateResult = "unavailable"
			return out
		}
		bound, result := session.BindPlanArtifact(ctx, out.Operation, core.AdministrativeArtifact{Path: request.ArtifactPath, Digest: contract.Hash(body), Length: uint64(len(body))})
		if result.Outcome != core.ObservedCurrent {
			out.Operation.Result = result
			out.Operation.StateResult = "refused"
			out.Operation.Plan = nil
			out.Delivery.PlanFailed = true
			return out
		}
		out.Operation = bound
	}
	return out
}
func abandonmentSourceFacts(pair *configuration.Pair, m *configuration.Model) (abandonmentSource, error) {
	if pair == nil || pair.Editable == nil || pair.Generated == nil || m == nil || !m.Resolved || m.FileID.IsZero() {
		return abandonmentSource{}, ErrAbandonmentPlan
	}
	basis, store, err := configurationPublicBasis(m)
	if err != nil {
		return abandonmentSource{}, err
	}
	control, err := basis.ControlCore(m.DomainID, store)
	if err != nil {
		return abandonmentSource{}, err
	}
	digest, err := core.AdministrativePublicBasisDigest(m.DomainID, store, basis)
	if err != nil {
		return abandonmentSource{}, err
	}
	pins, err := configurationSourcePins(pair, m)
	if err != nil {
		return abandonmentSource{}, err
	}
	return abandonmentSource{m.DomainID, store, basis, digest, control, pins}, nil
}
func defaultAbandonmentResources(ctx context.Context, m *configuration.Model, s abandonmentSource, mutation bool) (abandonmentResources, error) {
	return nativeAbandonmentResources(ctx, m, s, mutation, &http.Transport{TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second}, openNativeAbandonmentResources)
}

func nativeAbandonmentResources(ctx context.Context, m *configuration.Model, s abandonmentSource, mutation bool, transport *http.Transport,
	open func(context.Context, *configuration.Model, abandonmentSource, bool, *http.Transport, abandonmentResources) (abandonmentResources, error)) (abandonmentResources, error) {
	out := abandonmentResources{close: func() error { transport.CloseIdleConnections(); return nil }}
	return open(ctx, m, s, mutation, transport, out)
}

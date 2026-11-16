package compositionfull

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"enkv.sh/compositions/configuration"
	"enkv.sh/compositions/full/plugininstallation"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

var ErrPrepare = errors.New("configuration preparation incomplete")

// PrepareRequest selects one native source and its explicit representation.
// Recovery is absent for dependency preparation from an existing pair.
type PrepareRequest struct {
	Source   string
	Upgrade  bool
	Format   configuration.Format
	Recovery *PrepareRecoveryRequest
}

// PrepareRecoveryRequest supplies independent reconstruction inputs. Optional
// pointers distinguish omission from explicit empty text or a zero identity.
type PrepareRecoveryRequest struct {
	Name, Bucket, Region                          string
	Provider                                      contract.Family
	Prefix                                        *string
	NormalSigningKey, RecoverySigningKey          *string
	ExpectedDomain                                *contract.ID
	ExpectedOwner, ExpectedAuthorityEncryptionKey *string
}

type prepareError struct{ cause error }

func (e *prepareError) Error() string { return ErrPrepare.Error() }
func (e *prepareError) Unwrap() error { return errors.Join(ErrPrepare, e.cause) }

type prepareReconstructionError struct{ result core.Result }

func (e prepareReconstructionError) Error() string { return "configuration reconstruction refused" }

func validPrepareRequest(request PrepareRequest) bool {
	if len(request.Source) == 0 || len(request.Source) > 4096 || !utf8.ValidString(request.Source) || strings.ContainsRune(request.Source, 0) || !filepath.IsAbs(request.Source) || filepath.Clean(request.Source) != request.Source || request.Source == string(filepath.Separator) || request.Format != configuration.JSON && request.Format != configuration.YAML {
		return false
	}
	r := request.Recovery
	if r == nil {
		return true
	}
	if _, err := configuration.GeneratedPath(r.Name); err != nil {
		return false
	}
	if r.Prefix == nil || r.NormalSigningKey == nil && r.RecoverySigningKey == nil || r.ExpectedDomain != nil && r.ExpectedDomain.IsZero() || r.Provider != contract.AWS && r.Provider != contract.GCP || r.Provider != contract.AWS && r.ExpectedOwner != nil {
		return false
	}
	owner := ""
	if r.ExpectedOwner != nil {
		if *r.ExpectedOwner == "" {
			return false
		}
		owner = *r.ExpectedOwner
	}
	if !contract.StoreLocationValid(contract.StoreLocation{Provider: r.Provider, Region: r.Region, Bucket: r.Bucket, PrefixBeforeHEAD: *r.Prefix, ExpectedOwner: owner}) {
		return false
	}
	for _, key := range []*string{r.NormalSigningKey, r.RecoverySigningKey} {
		if key != nil && !contract.PublicKeySelectorValid(r.Provider, *key, true) {
			return false
		}
	}
	return r.ExpectedAuthorityEncryptionKey == nil || contract.PublicKeySelectorValid(r.Provider, *r.ExpectedAuthorityEncryptionKey, false)
}

// PrepareConfiguration prepares local declared artifacts or reconstructs into
// confirmed absent destinations. A surviving source remains unchanged. It has
// no remote write route.
func PrepareConfiguration(ctx context.Context, request PrepareRequest) (*PrepareResult, error) {
	return prepareConfiguration(ctx, request, NewDefaultReconstruction)
}

func prepareConfiguration(ctx context.Context, request PrepareRequest, open func(context.Context, ReconstructionConfig) (*core.ReconstructionEngine, error)) (result *PrepareResult, resultErr error) {
	result, resultErr = NewPrepareRefusal()
	if resultErr != nil {
		return result, resultErr
	}
	call := telemetry.Start(ctx, telemetry.ProviderApplication, telemetry.OpConfigurationPrepare)
	call.Checkpoint(telemetry.DiagnosticAdmission, telemetry.DiagnosticReasonNone)
	resultErr = runPrepareConfiguration(telemetry.CallContext(ctx, call), request, result, open)
	call.Finish(result.TelemetryResult(resultErr))
	if resultErr != nil {
		resultErr = &prepareError{cause: resultErr}
	}
	return result, resultErr
}

func runPrepareConfiguration(ctx context.Context, request PrepareRequest, result *PrepareResult, open func(context.Context, ReconstructionConfig) (*core.ReconstructionEngine, error)) error {
	if ctx == nil || open == nil || !validPrepareRequest(request) {
		return ErrPrepare
	}
	deadline, finite := ctx.Deadline()
	if !finite || deadline.IsZero() {
		return ErrPrepare
	}
	result.facts.Diagnostics = []prepareDiagnostic{}
	if err := ctx.Err(); err != nil {
		result.fail("cancelled", "request", "incomplete")
		return err
	}
	if !time.Now().Before(deadline) {
		result.fail("cancelled", "request", "incomplete")
		return context.DeadlineExceeded
	}
	// This exact path inspection distinguishes complete loss from source
	// capture failure; a missing companion cannot select absent-pair admission.
	info, err := os.Lstat(request.Source)
	if err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			result.fail("unsafe-path", "source", "refused")
			return ErrPrepare
		}
		return prepareExisting(ctx, request, result, open)
	}
	if !errors.Is(err, os.ErrNotExist) {
		result.fail("source-unavailable", "source", "incomplete")
		return err
	}
	if request.Recovery == nil {
		result.fail("invalid-request", "request", "refused")
		return ErrPrepare
	}
	return prepareAbsent(ctx, request, result, open)
}

func (r *PrepareResult) fail(reason, subject, outcome string) {
	r.facts.Outcome = outcome
	r.facts.Diagnostics = append(r.facts.Diagnostics, prepareDiagnostic{Reason: reason, Subject: subject})
}

func prepareExisting(ctx context.Context, request PrepareRequest, result *PrepareResult, open func(context.Context, ReconstructionConfig) (*core.ReconstructionEngine, error)) (resultErr error) {
	pair, err := configuration.Capture(ctx, request.Source, request.Format)
	if err != nil {
		if request.Recovery != nil && errors.Is(err, configuration.ErrSourceImageMissing) {
			return prepareMissingCompanion(ctx, request, result, open)
		}
		result.sourceFailure(ctx, err, false)
		return err
	}
	defer func() {
		if err := pair.Close(); err != nil {
			result.cleanupFailure()
			resultErr = errors.Join(resultErr, err)
		}
	}()
	model, err := configuration.ParseForPreparation(ctx, pair)
	if err != nil {
		result.sourceFailure(ctx, err, false)
		return err
	}
	defer func() { *model = configuration.Model{} }()
	if !model.Resolved {
		result.fail("source-invalid", "generated", "refused")
		return ErrPrepare
	}
	if _, _, err := configurationPublicBasis(model); err != nil {
		if ctx.Err() != nil {
			result.sourceFailure(ctx, ctx.Err(), false)
			return errors.Join(err, ctx.Err())
		}
		result.fail("trust-invalid", "source", "refused")
		return err
	}
	validation := validateInstalledConfiguration(ctx, model.Public)
	if !validation.Valid || !validation.DiagnosticsComplete {
		if ctx.Err() != nil {
			result.sourceFailure(ctx, ctx.Err(), false)
			return ctx.Err()
		} else {
			result.fail("source-invalid", "source", "refused")
		}
		return ErrPrepare
	}
	result.facts.Branch = "existing"
	if request.Recovery != nil {
		result.fail("invalid-request", "request", "refused")
		return ErrPrepare
	}
	result.facts.MissingInputs, model.MissingInputs = model.MissingInputs, nil
	return assessPrepareDependencies(ctx, pair, model, result, request.Upgrade)
}

func (r *PrepareResult) sourceFailure(ctx context.Context, err error, stability bool) {
	if !stability {
		if f := configurationSourceFailure("source", err); f != nil {
			r.facts.SourceFailure = f
		}
	}
	switch {
	case errors.Is(err, configuration.ErrPendingEdit):
		r.fail("pending-edit", "source", "incomplete")
	case errors.Is(err, configuration.ErrEditLocked):
		r.fail("contention", "source", "incomplete")
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded), ctx != nil && ctx.Err() != nil:
		r.fail("cancelled", "source", "incomplete")
	case stability && errors.Is(err, configuration.ErrSourceChanged):
		r.fail("source-changed", "source", "incomplete")
	case stability:
		r.fail("source-unavailable", "source", "incomplete")
	case errors.Is(err, configuration.ErrSourceImageMissing):
		r.fail("source-invalid", "source", "refused")
	case errors.Is(err, configuration.ErrSourceInvalid):
		r.fail("source-invalid", "source", "refused")
	default:
		r.fail("source-unavailable", "source", "incomplete")
	}
}

func (r *PrepareResult) cleanupFailure() {
	r.facts.Delivery.CleanupFailed = true
	if r.facts.Outcome == "complete" {
		r.facts.Outcome = "incomplete"
	}
	r.facts.Diagnostics = append(r.facts.Diagnostics, prepareDiagnostic{Reason: "cleanup-failed", Subject: "delivery"})
}

func prepareAbsent(ctx context.Context, request PrepareRequest, result *PrepareResult, open func(context.Context, ReconstructionConfig) (*core.ReconstructionEngine, error)) error {
	r := request.Recovery
	output, err := configuration.BeginReconstruction(ctx, request.Source, request.Format, r.Name)
	if err != nil {
		if !result.occupiedFailure(err) {
			result.sourceFailure(ctx, err, false)
		}
		return err
	}
	return prepareReconstructionOutput(ctx, request, result, open, output, nil)
}

func prepareReconstructionOutput(ctx context.Context, request PrepareRequest, result *PrepareResult, open func(context.Context, ReconstructionConfig) (*core.ReconstructionEngine, error), output *configuration.ReconstructionOutput, source *configuration.Model) (resultErr error) {
	r := request.Recovery
	result.facts.Branch = "reconstruction"
	defer func() {
		if source != nil {
			*source = configuration.Model{}
		}
		if err := output.Close(); err != nil {
			result.cleanupFailure()
			resultErr = errors.Join(resultErr, err)
		}
	}()
	if err := ctx.Err(); err != nil {
		result.fail("cancelled", "recovery", "incomplete")
		return err
	}
	if source != nil && !prepareRecoveryLayoutMatches(*r, source) {
		result.fail("invalid-request", "request", "refused")
		return ErrPrepare
	}
	if err := output.CheckUnchanged(ctx); err != nil {
		result.sourceFailure(ctx, err, true)
		return err
	}
	config := prepareReconstructionConfig(*r)
	engine, err := open(ctx, config)
	if err != nil || engine == nil {
		result.facts.Recovery.Status = "failed"
		return result.failPhase(ctx, errors.Join(ErrPrepare, err), "state-unavailable", "recovery")
	}
	defer engine.Close()
	projection, observed := engine.Reconstruct(ctx)
	if projection != nil {
		defer projection.Close()
	}
	if observed.Outcome != core.ObservedCurrent || projection == nil {
		result.facts.Recovery.Status = "failed"
		reason, outcome := "state-invalid", "incomplete"
		switch observed.Outcome {
		case core.AdmissionRefused:
			result.facts.Recovery.Status, reason, outcome = "refused", "trust-invalid", "refused"
		case core.EvidenceUnavailable, core.RootLossUnsupported:
			reason = "state-unavailable"
		case core.Contention:
			reason = "contention"
		}
		if ctx.Err() != nil {
			reason, outcome, result.facts.Recovery.Status = "cancelled", "incomplete", "failed"
		}
		result.fail(reason, "recovery", outcome)
		return errors.Join(prepareReconstructionError{result: observed}, ctx.Err())
	}
	provenance, ok := projection.Provenance()
	if !ok {
		result.facts.Recovery.Status = "failed"
		result.fail("state-invalid", "recovery", "incomplete")
		return ErrPrepare
	}
	result.facts.Recovery = prepareRecoveryFacts{Status: "complete", Domain: readerID(provenance.Domain), Head: readerID(provenance.HEADDigest)}
	basis, err := projection.CopyPublicBasis(ctx)
	if err != nil {
		return result.failPhase(ctx, err, "state-unavailable", "recovery")
	}
	var fileID contract.ID
	if _, err := rand.Read(fileID[:]); err != nil || fileID.IsZero() {
		clearReconstructionBasis(&basis)
		return result.failPhase(ctx, errors.Join(ErrPrepare, err), "delivery-failed", "delivery")
	}
	model, err := reconstructionConfigurationOwned(ctx, projection, basis, ReconstructionConfigurationOptions{Name: r.Name, FileID: fileID})
	projection.Close()
	if err != nil {
		return result.failPhase(ctx, err, "state-invalid", "recovery")
	}
	if source != nil {
		model, err = configuration.MergeReconstructedCompanion(ctx, source, model)
		if err != nil {
			result.sourceFailure(ctx, err, false)
			return err
		}
	}
	staged, err := output.Stage(ctx, model)
	if err != nil {
		if result.occupiedFailure(err) {
			return err
		}
		return result.failPhase(ctx, err, "delivery-failed", "delivery")
	}
	valid := false
	if source == nil {
		valid = validPreparedReconstruction(ctx, staged, request, provenance, fileID)
	} else {
		valid = validPreparedCompanionReconstruction(ctx, staged, request, provenance, fileID)
	}
	if !valid {
		return result.failPhase(ctx, ErrPrepare, "trust-invalid", "delivery")
	}
	result.facts.MissingInputs, staged.MissingInputs = staged.MissingInputs, nil
	delivery, err := output.Commit(ctx)
	if captureErr := result.captureDelivery(delivery, err); captureErr != nil {
		result.fail("delivery-unknown", "delivery", "unknown")
		return errors.Join(err, captureErr)
	}
	if err != nil {
		result.deliveryFailure(ctx, err)
		return err
	}
	pair, captured, err := output.Capture(ctx)
	if err != nil {
		result.sourceFailure(ctx, err, true)
		return err
	}
	return assessPrepareDependencies(ctx, pair, captured, result, request.Upgrade)
}

func (r *PrepareResult) occupiedFailure(err error) bool {
	var occupied *configuration.OccupiedEditTarget
	if !errors.As(err, &occupied) {
		return false
	}
	subject := "source"
	if occupied.Generated {
		subject = "generated"
	}
	r.fail("target-occupied", subject, "refused")
	return true
}

func (r *PrepareResult) failPhase(ctx context.Context, err error, reason, subject string) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
		r.fail("cancelled", subject, "incomplete")
		return errors.Join(err, ctx.Err())
	}
	r.fail(reason, subject, "incomplete")
	return err
}

func validPreparedReconstruction(ctx context.Context, model *configuration.Model, request PrepareRequest, provenance core.ReconstructionProvenance, fileID contract.ID) bool {
	return validPreparedReconstructionBasis(model, request, provenance, fileID) && validResolvedConfiguration(ctx, model)
}

func validPreparedCompanionReconstruction(ctx context.Context, model *configuration.Model, request PrepareRequest, provenance core.ReconstructionProvenance, fileID contract.ID) bool {
	if !validPreparedReconstructionBasis(model, request, provenance, fileID) {
		return false
	}
	validation := validateInstalledConfiguration(ctx, model.Public)
	return validation.Valid && validation.DiagnosticsComplete
}

func validPreparedReconstructionBasis(model *configuration.Model, request PrepareRequest, provenance core.ReconstructionProvenance, fileID contract.ID) bool {
	if model == nil || !model.Resolved || model.DomainID != provenance.Domain || model.FileID != fileID || model.DomainName != request.Recovery.Name || model.Provider != request.Recovery.Provider || model.Observation == nil || contract.Hash(model.Observation.Head) != provenance.HEADDigest || contract.Hash(model.Basis.HEAD) != provenance.HEADDigest {
		return false
	}
	if _, _, err := configurationPublicBasis(model); err != nil {
		return false
	}
	return true
}

func (r *PrepareResult) captureDelivery(delivery *configuration.PairDelivery, deliveryErr error) error {
	var unknown *configuration.UnknownEdit
	var pending *configuration.PendingEdit
	errors.As(deliveryErr, &unknown)
	errors.As(deliveryErr, &pending)
	if delivery == nil && unknown != nil {
		delivery, _ = unknown.Readback()
	}
	if delivery != nil {
		editable, generated, err := delivery.Digests()
		if err != nil {
			return err
		}
		ep, gp := delivery.Paths()
		r.facts.Delivery = prepareDeliveryFacts{Outcome: "recorded", EditablePath: ep, GeneratedPath: gp, Readback: &prepareReadbackFacts{EditableDigest: hex.EncodeToString(editable[:]), GeneratedDigest: hex.EncodeToString(generated[:])}, CleanupFailed: delivery.CleanupFailed()}
	} else if unknown != nil {
		r.facts.Delivery.Outcome = "unknown"
		if errors.Is(deliveryErr, configuration.ErrPendingEdit) {
			r.facts.Delivery.Outcome = "pending"
		}
	} else if pending != nil || errors.Is(deliveryErr, configuration.ErrPendingEdit) {
		r.facts.Delivery.Outcome = "pending"
	}
	for _, source := range []interface{ RecoverySource() (string, bool) }{delivery, unknown, pending} {
		if path, valid := source.RecoverySource(); valid {
			r.facts.Delivery.RecoverySource = path
			break
		}
	}
	return nil
}

func (r *PrepareResult) deliveryFailure(ctx context.Context, err error) {
	if r.facts.Delivery.Outcome == "recorded" {
		r.cleanupFailure()
		r.facts.Outcome = "incomplete"
		return
	}
	if r.facts.Delivery.Outcome == "pending" || r.facts.Delivery.Outcome == "unknown" {
		r.fail("delivery-unknown", "delivery", "unknown")
		return
	}
	if r.occupiedFailure(err) {
		return
	}
	if ctx.Err() != nil {
		r.fail("cancelled", "delivery", "incomplete")
		return
	}
	r.fail("delivery-failed", "delivery", "incomplete")
}

func assessPrepareDependencies(ctx context.Context, pair *configuration.Pair, model *configuration.Model, result *PrepareResult, upgrade bool) error {
	call := telemetry.Start(ctx, telemetry.ProviderApplication, telemetry.OpConfigurationPrepareDependencies)
	call.Checkpoint(telemetry.DiagnosticAdmission, telemetry.DiagnosticReasonNone)
	assessment, err := prepareDependencies(telemetry.CallContext(ctx, call), pair, model, upgrade)
	if len(model.MissingInputs) != 0 {
		result.facts.MissingInputs, model.MissingInputs = model.MissingInputs, nil
	}
	if len(result.facts.MissingInputs) != 0 {
		assessment.AllDeclaredReady = false
	}
	if assessment.Requirements == nil {
		assessment.Requirements = []PrepareDependencyRequirement{}
	}
	if assessment.Installations == nil {
		assessment.Installations = []plugininstallation.Installation{}
	}
	result.facts.Dependencies = assessment
	if err != nil && (errors.Is(err, ErrPrepareSourceCheck) || ctx.Err() != nil) {
		result.facts.Dependencies.MinimumAdministrativeReady, result.facts.Dependencies.AllDeclaredReady = false, false
		result.sourceFailure(ctx, err, true)
		call.Finish(prepareTelemetryResult(err))
		return err
	}
	result.facts.Outcome = "incomplete"
	statuses := make([]string, 0, len(assessment.Requirements)+len(assessment.Installations))
	for _, row := range assessment.Requirements {
		statuses = append(statuses, row.Status)
	}
	for _, row := range assessment.Installations {
		statuses = append(statuses, row.Status)
	}
	for _, status := range statuses {
		reason := "dependency-invalid"
		switch status {
		case "verified", "not-attempted":
			continue
		case "missing":
			reason = "dependency-missing"
		case "unavailable":
			reason = "dependency-unavailable"
		}
		found := false
		for _, d := range result.facts.Diagnostics {
			found = found || d.Reason == reason && d.Subject == "dependencies"
		}
		if !found {
			result.facts.Diagnostics = append(result.facts.Diagnostics, prepareDiagnostic{Reason: reason, Subject: "dependencies"})
		}
	}
	if assessment.AllDeclaredReady && err == nil {
		result.facts.Outcome = "complete"
	} else if err != nil && len(result.facts.Diagnostics) == 0 && assessment.SettingsFailure == nil {
		result.fail("dependency-unavailable", "dependencies", "incomplete")
	}
	status := telemetry.ResultFailure
	if result.facts.Outcome == "complete" {
		status = telemetry.ResultSuccess
	} else if result.SetupRequired() {
		status = telemetry.ResultSetupIncomplete
	}
	call.Finish(status)
	return err
}

func prepareTelemetryResult(err error) telemetry.Result {
	if err == nil {
		return telemetry.ResultSuccess
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return telemetry.ResultCancelled
	}
	return telemetry.ResultFailure
}

func prepareReconstructionConfig(r PrepareRecoveryRequest) ReconstructionConfig {
	route := contract.Hash([]byte("enkv/prepare/default-credential-route/v1\x00" + r.Region + "\x00" + r.Bucket + "\x00" + *r.Prefix))
	var domain contract.ID
	if r.ExpectedDomain != nil {
		domain = *r.ExpectedDomain
	}
	kek := ""
	if r.ExpectedAuthorityEncryptionKey != nil {
		kek = *r.ExpectedAuthorityEncryptionKey
	}
	return selectPrepareReconstruction(r, domain, kek, route)
}

package compositionfull

import (
	"context"
	"errors"
	"path/filepath"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/compositions/outputhost"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// MaintenanceCommandResult separates canonical mutation, local delivery and
// subsequent source observation. Adoption of the delivered pair is explicit.
type MaintenanceCommandResult struct {
	SourceFailure *ConfigurationSourceFailure
	core.PublicApplyResult
	Observation     *core.PublicMaintenanceObservationResult
	Delivery        ReplacementCommandDelivery
	SourceUsability string
	OutputPins      *core.AdministrativeSourcePins
	localDelivery   *configuration.PairDelivery
}

func configureMaintenanceOutput(ctx context.Context, pair *configuration.Pair, model *configuration.Model, installed *core.AccessMutationInstallation, output *configuration.MaintenanceOutput, request configuration.MaintenanceRequest) error {
	if output == nil || output.Existing() != nil {
		return configuration.ErrEdit
	}
	if output.Request() != request {
		return configuration.ErrEdit
	}
	identity := output.SourceIdentity()
	if pair == nil || pair.Editable == nil || pair.Generated == nil || identity.Format != pair.Format || identity.Editable != (contract.DigestLength{Digest: contract.ID(pair.Editable.Digest()), Length: uint64(pair.Editable.Size())}) || identity.Generated != (contract.DigestLength{Digest: contract.ID(pair.Generated.Digest()), Length: uint64(pair.Generated.Size())}) {
		return configuration.ErrEdit
	}
	if err := output.CheckUnchanged(ctx); err != nil {
		return err
	}
	plugins, interpret, err := configurationNormalizePluginsWithOutputValidator(ctx, pair, output.CheckUnchanged, model, nil, outputhost.NewPublicValidator)
	if err != nil {
		return err
	}
	if interpret != nil {
		installed.ConfigurationValidator = core.NewPublicConfigurationValidator(interpret)
	}
	pins, err := replacementObservationPins(pair, model)
	if err != nil {
		return err
	}
	apply, _, err := configurationApplyInput(model)
	if err != nil {
		return err
	}
	inputs := configurationPlanningInputs(model)
	digest, err := core.PlanningInputDigest(model.Public, inputs)
	if err != nil {
		return err
	}
	expected := apply.ExpectedControl
	domain, provider, location := model.DomainID, model.Provider, model.Store
	installed.Maintenance = &core.MaintenanceInstallation{
		SourcePins: pins, OutputPath: output.Path(), InputDigest: digest, Configuration: model.Public, Inputs: inputs, Recipients: apply.DesiredRecipients,
		CredentialRoute: contract.Hash(append([]byte("enkv/planning/authority-credential-route/v1\x00"), model.DomainID[:]...)),
		SourceUnchanged: output.CheckUnchanged,
	}
	installed.Maintenance.AdmitFeasibility = func(ctx context.Context, admission contract.PlanningAdmission) (core.PlanningCustody, error) {
		return openMaintenancePlanningCustody(ctx, domain, provider, location, expected, admission)
	}
	installed.Maintenance.PublishSuccessor = func(ctx context.Context, successor core.MaintenanceSuccessor) (core.MaintenanceReadback, error) {
		material := configuration.MaintenanceMaterial{RequestIdentity: successor.RequestIdentity, SignedCandidate: successor.SignedCandidate, Retirement: successor.Retirement, RekeyTarget: successor.RekeyTarget, PredecessorHead: successor.PredecessorHead, PredecessorRoot: successor.PredecessorRoot, CandidateRoot: successor.CandidateRoot, BeforeGeneration: successor.BeforeGeneration, AfterGeneration: successor.AfterGeneration}
		for _, page := range successor.PredecessorPages {
			material.PredecessorPages = append(material.PredecessorPages, configuration.MaintenanceValuePage{Index: page.Index, Body: page.Body})
		}
		for _, page := range successor.CandidatePages {
			material.CandidatePages = append(material.CandidatePages, configuration.MaintenanceValuePage{Index: page.Index, Body: page.Body})
		}
		for _, delta := range successor.PinDeltas {
			material.PinDeltas = append(material.PinDeltas, configuration.MaintenancePinDelta{Name: delta.Name, Before: delta.Before, After: delta.After})
		}
		readback, err := output.Publish(ctx, material)
		if err != nil {
			return core.MaintenanceReadback{}, err
		}
		return maintenanceReadback(ctx, pair, readback, output.Path(), plugins, output.CheckUnchanged)
	}
	return nil
}

func maintenanceCorrelation(model *configuration.Model) (core.MaintenanceSuccessor, error) {
	if model == nil || model.Maintenance == nil {
		return core.MaintenanceSuccessor{}, configuration.ErrEdit
	}
	metadata := model.Maintenance
	head, err := metadata.Candidate()
	if err != nil {
		return core.MaintenanceSuccessor{}, err
	}
	out := core.MaintenanceSuccessor{OperationKind: metadata.Request.OperationKind, Recipient: contract.RecipientBindingReference{RecipientID: metadata.Request.RecipientID, PublicBindingDigest: metadata.Request.BindingDigest}, Name: metadata.Request.Name,
		FileIdentity: model.FileID, DomainID: model.DomainID, OperationID: head.Subject.Operation, RequestIdentity: metadata.RequestIdentity, SignedCandidate: metadata.SignedCandidate, PredecessorHead: metadata.PredecessorHead, PredecessorRoot: metadata.PredecessorRoot, CandidateRoot: metadata.CandidateRoot, BeforeGeneration: metadata.BeforeGeneration, AfterGeneration: metadata.AfterGeneration}
	for _, page := range metadata.PredecessorPages {
		out.PredecessorPages = append(out.PredecessorPages, core.MaintenanceValuePage{Index: page.Index, Body: page.Body})
	}
	for _, page := range metadata.CandidatePages {
		out.CandidatePages = append(out.CandidatePages, core.MaintenanceValuePage{Index: page.Index, Body: page.Body})
	}
	for _, delta := range metadata.PinDeltas {
		out.PinDeltas = append(out.PinDeltas, core.MaintenancePinDelta{Name: delta.Name, Before: delta.Before, After: delta.After})
	}
	// The exact target is signed as part of the lifecycle subject.
	out.RekeyTarget, out.Retirement = metadata.RekeyTarget, metadata.Retirement
	return out, nil
}

func maintenanceReadback(ctx context.Context, trusted *configuration.Pair, readback *configuration.SuccessorReadback, outputPath string, plugins *configurationInstalledPlugins, checkSource func(context.Context) error) (core.MaintenanceReadback, error) {
	if readback == nil || readback.Pair == nil || readback.Model == nil {
		return core.MaintenanceReadback{}, configuration.ErrEdit
	}
	if err := readback.Pair.CheckUnchanged(ctx); err != nil {
		return core.MaintenanceReadback{}, err
	}
	model := readback.Model
	if model.Maintenance == nil {
		return core.MaintenanceReadback{}, configuration.ErrEdit
	}
	if _, _, err := configurationNormalizePluginsWithOutputValidator(ctx, trusted, checkSource, model, plugins, outputhost.NewPublicValidator); err != nil {
		return core.MaintenanceReadback{}, err
	}
	metadata := model.Maintenance
	sourcePins := core.AdministrativeSourcePins{FileID: metadata.FileID, Format: uint8(metadata.Source.Format), EditableDigest: metadata.Source.Editable.Digest, EditableLength: metadata.Source.Editable.Length, GeneratedDigest: metadata.Source.Generated.Digest, GeneratedLength: metadata.Source.Generated.Length, HasGenerated: true}
	basis, _, err := configurationPublicBasis(model)
	if err != nil {
		return core.MaintenanceReadback{}, err
	}
	pins, err := replacementObservationPins(readback.Pair, model)
	if err != nil {
		return core.MaintenanceReadback{}, err
	}
	apply, _, err := configurationApplyInput(model)
	if err != nil {
		return core.MaintenanceReadback{}, err
	}
	correlation, err := maintenanceCorrelation(model)
	if err != nil {
		return core.MaintenanceReadback{}, err
	}
	return core.MaintenanceReadback{SourcePins: sourcePins, OutputPins: pins, OutputPath: outputPath, Basis: basis, Configuration: model.Public, Inputs: configurationPlanningInputs(model), Recipients: apply.DesiredRecipients, Correlation: correlation}, nil
}

func runConfigurationMaintenance(ctx context.Context, nonce contract.ID, sourcePath string, encoding configuration.Format, request configuration.MaintenanceRequest, outputPath string,
	openObservation func(context.Context, *configuration.Model) (core.PublicSelectedReader, func() error, error)) (out MaintenanceCommandResult) {
	out.Delivery.Status, out.SourceUsability = "not-attempted", "unchecked"
	var protected *configuration.MaintenanceRequest
	refuse := func(stage string, err error) {
		if protected != nil {
			observed := maintenanceObservationRefusal(ctx, nonce, protected.OperationKind, encoding, stage, err)
			out.Observation = &observed
			out.PublicApplyResult = core.PublicApplyResult{RequestID: nonce, OperationID: observed.OperationID, Result: observed.Result}
			if f := configurationSourceFailure("source", err); f != nil && validConfigurationAdmissionSourceFailure(f, observed.PreAdmission, observed.RequestIdentity, observed.Result) {
				out.SourceFailure = f
			}
			return
		}
		result, construction := newConfigurationApplyResult(nonce, encoding)
		if construction == nil {
			result = configurationApplyFailure(ctx, result, stage, err)
		}
		out.PublicApplyResult = result
		if f := configurationSourceFailure("source", err); f != nil && validConfigurationAdmissionSourceFailure(f, result.PreAdmission, result.RequestIdentity, result.Result) {
			out.SourceFailure = f
		}
	}

	if !configuration.SuccessorOutputPathValid(outputPath) || !filepath.IsAbs(sourcePath) || filepath.Clean(sourcePath) != sourcePath {
		refuse("dispatch", configuration.ErrEdit)
		return out
	}
	out.Delivery.Path = outputPath
	if ctx == nil || ctx.Err() != nil || nonce.IsZero() {
		refuse("context", nil)
		return out
	}
	if deadline, ok := ctx.Deadline(); !ok || !time.Now().Before(deadline) {
		refuse("context", context.DeadlineExceeded)
		return out
	}
	capture, err := configuration.CaptureMaintenanceOutput(ctx, outputPath, encoding)
	if err != nil {
		var known *configuration.MaintenanceOutputRefusal
		if errors.As(err, &known) {
			protected = &known.Request
			out.Delivery.Status = "existing"
		}
		refuse("capture", err)
		return out
	}
	var output *configuration.MaintenanceOutput
	var pair *configuration.Pair
	var sourceFileID contract.ID
	defer func() {
		var closeErr error
		if output != nil {
			if output.Delivered() || output.Existing() != nil {
				identity, err := output.OutputIdentity()
				fileID := sourceFileID
				if out.Successor != nil {
					fileID = out.Successor.FileIdentity
				} else if output.Existing() != nil {
					fileID = output.Existing().FileID
				}
				if err != nil || fileID.IsZero() {
					out.Delivery.Failed = true
				} else {
					out.OutputPins = &core.AdministrativeSourcePins{FileID: fileID, Format: uint8(identity.Format), EditableDigest: identity.Editable.Digest, EditableLength: identity.Editable.Length, GeneratedDigest: identity.Generated.Digest, GeneratedLength: identity.Generated.Length, HasGenerated: true}
				}
			}
			closeErr = output.Close()
			out.localDelivery = output.LocalDelivery()
			if out.localDelivery != nil {
				out.Delivery.CleanupFailed = out.Delivery.CleanupFailed || out.localDelivery.CleanupFailed()
			}
			if out.localDelivery != nil && !output.Delivered() {
				out.Delivery.Status = "read-back"
				out.Delivery.Failed = true
			}
			if source, pending := output.RecoverySource(); pending {
				out.Delivery.Status = "pending"
				out.Delivery.RecoverySource = source
				out.Delivery.Failed = true
			}
		} else {
			closeErr = capture.Close()
		}
		if pair != nil {
			closeErr = errors.Join(closeErr, pair.Close())
		}
		if closeErr != nil {
			out.Delivery.CleanupFailed = true
		}
	}()
	fixed, existing := capture.Request()
	if existing {
		protected = &fixed
		out.Delivery.Status = "existing"
	}
	pair, err = configuration.Capture(ctx, sourcePath, encoding)
	if err != nil {
		refuse("capture", err)
		return out
	}
	model, parseErr := configuration.Parse(ctx, pair)
	if parseErr != nil {
		refuse("parse", parseErr)
		return out
	}
	sourceFileID = model.FileID
	if request.OperationKind == contract.OperationRetireRecipientIdentity {
		if request.RecipientReference == "" && !request.RecipientID.IsZero() {
			reference, refErr := (RecipientSelector{ID: request.RecipientID}).localReference(ctx, pair)
			if refErr != nil {
				refuse("declaration", refErr)
				return out
			}
			request.RecipientReference = reference
		}
		recipient, refErr := configurationRecipientReference(model, request.RecipientReference)
		if refErr != nil {
			refuse("declaration", refErr)
			return out
		}
		request.RecipientID, request.BindingDigest = recipient.RecipientID, recipient.PublicBindingDigest
	}
	output, err = configuration.PrepareMaintenanceOutputFromCapture(ctx, pair, capture, request)
	if err != nil {
		refuse("declaration", err)
		return out
	}
	out.Delivery.Path = output.Path()
	releaseConfigurationSource(model)
	if existing {
		observed, err := observeMaintenanceConfiguration(ctx, nonce, pair, output, openObservation)
		out.Observation = &observed
		out.Result = observed.Result
		out.RequestID, out.OperationID, out.RequestIdentity, out.DomainID = observed.RequestID, observed.OperationID, observed.RequestIdentity, observed.DomainID
		if observed.SourceUsabilityChecked {
			if observed.SourceUsable {
				out.SourceUsability = "confirmed"
			} else {
				out.SourceUsability = "unusable"
			}
		}
		if err != nil {
			out.Delivery.Failed = true
		}
		return out
	}
	out.Delivery.Status = "unproved"
	switch request.OperationKind {
	case contract.OperationEnvelopeRekey:
		out.PublicApplyResult = RekeyConfigurationEnvelope(ctx, nonce, pair, request.Name, output)
	case contract.OperationRetireRecipientIdentity:
		out.PublicApplyResult = RetireConfigurationRecipient(ctx, nonce, pair, request.RecipientReference, output)
	default:
		refuse("dispatch", configuration.ErrEdit)
	}
	if output.Delivered() {
		out.Delivery.Status = "delivered"
	}
	if out.Result.Outcome == core.ObservedCurrent && output.Delivered() {
		out.SourceUsability = "confirmed"
	}
	return out
}

package compositionfull

import (
	"context"
	"slices"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// ApplyPublicationOptions selects retained executors and post-unknown
// authorization. Core independently discovers eligible deletion coordinates.
type ApplyPublicationOptions struct {
	RepublishAfterUnknown []contract.ID
	DeletePlugins         map[contract.ID]string
}

func ownApplyPublicationOptions(input ApplyPublicationOptions) (ApplyPublicationOptions, error) {
	if len(input.RepublishAfterUnknown) > contract.MaxPublicationMarkers {
		return ApplyPublicationOptions{}, contract.ErrRecordCapacity
	}
	seen := make(map[contract.ID]bool, len(input.RepublishAfterUnknown))
	for _, id := range input.RepublishAfterUnknown {
		if id.IsZero() || seen[id] {
			return ApplyPublicationOptions{}, contract.ErrRecord
		}
		seen[id] = true
	}
	choices, err := ownDeletionPluginChoices(input.DeletePlugins)
	if err != nil {
		return ApplyPublicationOptions{}, err
	}
	return ApplyPublicationOptions{RepublishAfterUnknown: slices.Clone(input.RepublishAfterUnknown), DeletePlugins: choices}, nil
}

// ApplyConfigurationAndPublish keeps the captured pair and both installed
// owners alive through the two synchronous operations under one deadline.
func ApplyConfigurationAndPublish(ctx context.Context, applyRequestID, publicationRequestID contract.ID, pair *configuration.Pair, publication ApplyPublicationOptions, options ApplyOptions) (out ConfigurationApplyPublicationResult) {
	out.PublicApplyPublicationResult = configurationApplyPublication(ctx, applyRequestID, publicationRequestID, pair, contract.ID{}, publication, configurationApplyPublicationOpener(pair, contract.ID{}, options), configurationPublicationOpener(pair), configurationMutationResultFacts{&out.SourceFailure, &out.storeLocation})
	return out
}

func ContinueConfigurationApplyAndPublish(ctx context.Context, applyRequestID, operationID, publicationRequestID contract.ID, pair *configuration.Pair, publication ApplyPublicationOptions) (out ConfigurationApplyPublicationResult) {
	if operationID.IsZero() {
		var format configuration.Format
		if pair != nil {
			format = pair.Format
		}
		return ConfigurationApplyPublicationResult{PublicApplyPublicationResult: configurationApplyPublicationRefusal(applyRequestID, format)}
	}
	out.PublicApplyPublicationResult = configurationApplyPublication(ctx, applyRequestID, publicationRequestID, pair, operationID, publication, configurationApplyPublicationOpener(pair, operationID, ApplyOptions{}), configurationPublicationOpener(pair), configurationMutationResultFacts{&out.SourceFailure, &out.storeLocation})
	return out
}

func configurationApplyPublicationRefusal(requestID contract.ID, format configuration.Format) core.PublicApplyPublicationResult {
	apply, _ := newConfigurationApplyResult(requestID, format)
	return core.PublicApplyPublicationResult{Apply: apply, Publication: core.ApplyPublicationStage{Stage: "unstarted", Reason: "apply-incomplete"}}
}

func configurationApplyPublication(ctx context.Context, applyRequestID, publicationRequestID contract.ID, pair *configuration.Pair, operationID contract.ID, publication ApplyPublicationOptions,
	openApply configurationApplyOpener,
	openPublication func(context.Context, *configuration.Model, core.PublicationInstallation, map[contract.ID]string, *configurationInstalledPlugins) (*core.InstalledPublication, error), resultFacts ...configurationMutationResultFacts) core.PublicApplyPublicationResult {
	var format configuration.Format
	if pair != nil {
		format = pair.Format
	}
	apply, err := newConfigurationApplyResult(applyRequestID, format)
	out := core.PublicApplyPublicationResult{Apply: apply, Publication: core.ApplyPublicationStage{Stage: "unstarted", Reason: "apply-incomplete"}}
	if err != nil {
		return out
	}
	owned, err := ownApplyPublicationOptions(publication)
	if err != nil {
		return out
	}
	m, err := configuration.Parse(ctx, pair)
	if err != nil {
		out.Apply = configurationApplyFailure(ctx, apply, "parse", err, mutationSourceFailureTarget(resultFacts))
		return out
	}
	var installation core.ApplyInstallation
	var input []core.ApplyEntryInput
	var plugins *configurationInstalledPlugins
	if operationID.IsZero() {
		var interpret core.PublicOutputInterpreter
		plugins, interpret, err = configurationNormalizePlugins(ctx, pair, pair, m)
		if err == nil {
			installation, input, err = configurationApplyInput(m)
			installation.ConfigurationValidator = core.NewPublicConfigurationValidator(interpret)
		}
	} else {
		installation, err = configurationAcceptedGeneratedInput(m)
	}
	if err != nil {
		out.Apply = configurationApplyFailure(ctx, apply, "declaration", err, mutationSourceFailureTarget(resultFacts))
		return out
	}
	if ctx == nil || ctx.Err() != nil || applyRequestID.IsZero() || publicationRequestID.IsZero() || openApply == nil {
		out.Apply = configurationApplyFailure(ctx, apply, "context", nil, mutationSourceFailureTarget(resultFacts))
		return out
	}
	if deadline, finite := ctx.Deadline(); !finite || !time.Now().Before(deadline) {
		out.Apply = configurationApplyFailure(ctx, apply, "context", &configuration.Diagnostic{Reason: "expired"}, mutationSourceFailureTarget(resultFacts))
		return out
	}
	engine, err := openApply(ctx, m, installation, plugins)
	if err != nil || engine == nil {
		out.Apply = configurationAccessMutationUnavailable(ctx, apply)
		return out
	}
	defer engine.Close()
	var publisher *core.InstalledPublication
	publicationConstructionFailed := false
	if openPublication != nil {
		// Construction is independent of effects. A failed publisher cannot gate
		// the already requested apply; Core will preserve an unstarted stage.
		publisher, err = openPublication(ctx, m, core.PublicationInstallation{ExpectedDomain: installation.ExpectedDomain, ExpectedStore: installation.ExpectedStore,
			PublicBasis: installation.PublicBasis, ExpectedControl: installation.ExpectedControl, CompositionID: installation.CompositionID}, owned.DeletePlugins, plugins)
		publicationConstructionFailed = err != nil || publisher == nil
		if err != nil && publisher != nil {
			publisher.Close()
			publisher = nil
		}
		if publisher != nil {
			defer publisher.Close()
		}
	}
	if operationID.IsZero() {
		out = engine.ApplyAndPublish(ctx, applyRequestID, publicationRequestID, input, publisher, owned.RepublishAfterUnknown)
	} else {
		out = engine.ContinueAndPublish(ctx, applyRequestID, operationID, publicationRequestID, publisher, owned.RepublishAfterUnknown)
	}
	if publicationConstructionFailed && out.Publication.Stage == "unstarted" && out.Publication.Reason == "selection-unavailable" {
		out.Apply.Diagnostics = append(out.Apply.Diagnostics, contract.Diagnostic{Subject: contract.DiagnosticSubject{Kind: contract.SubjectOutputBinding}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonEvidenceUnavailable})
	}
	if out.Apply.RequestIdentity.IsZero() {
		if out.Apply.OperationID.IsZero() {
			out.Apply.OperationID = apply.OperationID
		}
		apply.PreAdmission.Stage = "apply"
		apply.PreAdmission.Code = string(configurationMutationObservationReason(ctx, out.Apply.Result))
		out.Apply.PreAdmission = apply.PreAdmission
	}
	retainMutationStoreLocation(resultFacts, m, out.Apply)
	return out
}

func ApplyConfigurationAndPublishFile(ctx context.Context, applyRequestID, publicationRequestID contract.ID, path string, format configuration.Format, publication ApplyPublicationOptions, options ApplyOptions) ConfigurationApplyPublicationResult {
	return configurationApplyPublicationFile(ctx, applyRequestID, publicationRequestID, path, format, contract.ID{}, publication, options)
}

func ContinueConfigurationApplyAndPublishFile(ctx context.Context, applyRequestID, operationID, publicationRequestID contract.ID, path string, format configuration.Format, publication ApplyPublicationOptions) ConfigurationApplyPublicationResult {
	if operationID.IsZero() {
		return ConfigurationApplyPublicationResult{PublicApplyPublicationResult: configurationApplyPublicationRefusal(applyRequestID, format)}
	}
	return configurationApplyPublicationFile(ctx, applyRequestID, publicationRequestID, path, format, operationID, publication, ApplyOptions{})
}

func configurationApplyPublicationFile(ctx context.Context, applyRequestID, publicationRequestID contract.ID, path string, format configuration.Format, operationID contract.ID, publication ApplyPublicationOptions, options ApplyOptions) (out ConfigurationApplyPublicationResult) {
	apply, err := newConfigurationApplyResult(applyRequestID, format)
	out.PublicApplyPublicationResult = core.PublicApplyPublicationResult{Apply: apply, Publication: core.ApplyPublicationStage{Stage: "unstarted", Reason: "apply-incomplete"}}
	if err != nil {
		return out
	}
	owned, err := ownApplyPublicationOptions(publication)
	if err != nil {
		return out
	}
	pair, err := configuration.Capture(ctx, path, format)
	if err != nil {
		out.Apply = configurationApplyFailure(ctx, apply, "capture", err, &out.SourceFailure)
		return out
	}
	defer func() {
		if err := pair.Close(); err != nil {
			out.Apply.AddCleanupDiagnostic()
		}
	}()
	out.PublicApplyPublicationResult = configurationApplyPublication(ctx, applyRequestID, publicationRequestID, pair, operationID, owned, configurationApplyPublicationOpener(pair, operationID, options), configurationPublicationOpener(pair), configurationMutationResultFacts{&out.SourceFailure, &out.storeLocation})
	return out
}

func configurationApplyPublicationOpener(pair *configuration.Pair, operationID contract.ID, options ApplyOptions) configurationApplyOpener {
	if operationID.IsZero() {
		return configurationCurrentApplyOpener(pair, options)
	}
	return func(ctx context.Context, m *configuration.Model, i core.ApplyInstallation, _ *configurationInstalledPlugins) (*core.InstalledApply, error) {
		return openConfigurationApply(ctx, m, i)
	}
}

func configurationPublicationOpener(pair *configuration.Pair) func(context.Context, *configuration.Model, core.PublicationInstallation, map[contract.ID]string, *configurationInstalledPlugins) (*core.InstalledPublication, error) {
	return func(ctx context.Context, m *configuration.Model, i core.PublicationInstallation, choices map[contract.ID]string, captured *configurationInstalledPlugins) (*core.InstalledPublication, error) {
		return openConfigurationPublication(ctx, pair, m, i, choices, captured)
	}
}

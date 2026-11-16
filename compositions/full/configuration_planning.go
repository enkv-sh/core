package compositionfull

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	privatecrypto "enkv.sh/crypto"
)

// PlanConfiguration borrows both exact captured pairs until private custody joins.
// Only the trusted pair supplies public trust and provider construction.
func PlanConfiguration(ctx context.Context, requestID contract.ID, trusted, candidate *configuration.Pair, options contract.PlanningOptions) ConfigurationPlanningResult {
	return planConfiguration(ctx, requestID, trusted, candidate, options, nil, NewDefaultPlanning)
}

func planConfiguration(ctx context.Context, requestID contract.ID, trusted, candidate *configuration.Pair, options contract.PlanningOptions, factory privatecrypto.PlanningDisplayFactory,
	open func(context.Context, PlanningConfig) (*core.InstalledPlanning, error)) (out ConfigurationPlanningResult) {
	defer func() { finishPublicationPlanningRequest(&out, options.Publish) }()
	var format configuration.Format
	if trusted != nil {
		format = trusted.Format
	}
	correlation, err := newConfigurationComparisonResult(requestID, format)
	if err != nil {
		return configurationPlanningResult(correlation)
	}
	return planConfigurationWithIdentity(ctx, requestID, trusted, candidate, options, factory, open, correlation)
}

func planConfigurationWithIdentity(ctx context.Context, requestID contract.ID, trusted, candidate *configuration.Pair, options contract.PlanningOptions, factory privatecrypto.PlanningDisplayFactory,
	open func(context.Context, PlanningConfig) (*core.InstalledPlanning, error), correlation ConfigurationComparisonResult) (out ConfigurationPlanningResult) {
	defer func() { finishConfigurationPlanning(&out, correlation) }()
	defer func() { finishPublicationPlanningRequest(&out, options.Publish) }()
	q := correlation.PreAdmission
	q.Stage = "parse"
	baseline, err := configuration.Parse(ctx, trusted)
	if err != nil {
		return configurationPlanningFailure(ctx, requestID, contract.ID{}, "trusted", err)
	}
	if !baseline.Resolved {
		return configurationPlanningFailure(ctx, requestID, baseline.DomainID, "trusted", &configuration.Diagnostic{Field: "generated", Reason: "restore-exact-generated-file"})
	}
	desired, proposedPair := baseline, trusted
	if candidate != nil {
		q.Format = configurationSourceFormat(candidate.Format)
		desired, err = configuration.Parse(ctx, candidate)
		if err != nil {
			return configurationPlanningFailure(ctx, requestID, baseline.DomainID, "candidate", err)
		}
		proposedPair = candidate
	}
	requirements := compareConfigurationRequirements(baseline, desired)
	defer func() { out.InstallationRequirements = requirements }()
	if !desired.Resolved {
		return configurationPlanningFailure(ctx, requestID, baseline.DomainID, "candidate", &configuration.Diagnostic{Field: "generated", Reason: "restore-exact-generated-file"})
	}
	q.Format = configurationSourceFormat(trusted.Format)
	q.Stage = "public-basis"
	reader, err := configurationReaderConfig(baseline)
	if err != nil {
		return configurationPlanningFailure(ctx, requestID, baseline.DomainID, "trusted", err)
	}
	q.Stage = "context"
	if ctx == nil || ctx.Err() != nil || requestID.IsZero() || open == nil || !options.Valid() || options.Purpose != contract.PlanningEquality && options.Purpose != contract.PlanningDisplay || (options.Purpose == contract.PlanningDisplay) != (factory != nil) {
		return configurationPlanningFailure(ctx, requestID, baseline.DomainID, "trusted", nil)
	}
	if deadline, finite := ctx.Deadline(); !finite || !time.Now().Before(deadline) {
		return configurationPlanningFailure(ctx, requestID, baseline.DomainID, "trusted", context.DeadlineExceeded)
	}
	q.Stage = "public-configuration"
	baselineValidation, selectPolicy, err := configurationNormalizationValidation(ctx, trusted, trusted, baseline)
	if err != nil {
		return configurationPlanningFailure(ctx, requestID, baseline.DomainID, "trusted", err)
	}
	validations := []core.PublicConfigurationValidation{baselineValidation}
	valid := baselineValidation.Valid && baselineValidation.Complete && baselineValidation.DiagnosticsComplete
	if candidate != nil {
		validation, candidateSelector, err := configurationNormalizationValidation(ctx, trusted, proposedPair, desired)
		if err != nil {
			return configurationPlanningFailure(ctx, requestID, baseline.DomainID, "candidate", err)
		}
		selectPolicy = candidateSelector
		validations = append(validations, validation)
		valid = valid && validation.Valid && validation.Complete && validation.DiagnosticsComplete
	}
	if !valid {
		if candidate != nil && candidate.Format != trusted.Format {
			q.Format = ""
		}
		return configurationPlanningResult(ConfigurationComparisonResult{PublicComparisonResult: core.RefusePublicComparisonSource(requestID, baseline.DomainID, validations...)})
	}
	inputs := configurationPlanningInputs(desired)
	inputDigest, err := core.PlanningInputDigest(desired.Public, inputs)
	if err != nil {
		return configurationPlanningFailure(ctx, requestID, baseline.DomainID, "candidate", err)
	}
	reader.SelectPolicyAction = selectPolicy
	installed, err := configurationPlanningConfig(baseline, reader)
	if err != nil {
		return configurationPlanningFailure(ctx, requestID, baseline.DomainID, "trusted", err)
	}
	installed.Sources = contract.PlanningSources{Trusted: configurationPlanningSource(trusted, baseline), Proposed: configurationPlanningSource(proposedPair, desired)}
	installed.FileIdentity, installed.InputDigest = desired.FileID, inputDigest
	installed.DisplayFactory = factory
	q.Stage = "construction"
	planner, err := open(ctx, installed)
	if err != nil || planner == nil {
		return configurationPlanningResult(configurationComparisonUnavailable(ctx, requestID, baseline.DomainID, "trusted"))
	}
	defer planner.Close()
	input := desired.Public
	beforeNames, afterNames := configurationRecipientNames(baseline), configurationRecipientNames(desired)
	if desired != baseline {
		releaseConfigurationSource(desired)
	}
	releaseConfigurationSource(baseline)
	q.Stage = "compare"
	result := ConfigurationPlanningResult{PlanningResult: planner.Plan(ctx, requestID, input, inputs, options)}
	addConfigurationRecipientNames(&result.ComparisonPayload, beforeNames, afterNames)
	return result
}

func configurationPlanningInputs(model *configuration.Model) []contract.PlanningInput {
	var inputs []contract.PlanningInput
	for _, row := range model.Entries {
		if !row.Secret || row.Generated != nil {
			continue
		}
		input := contract.PlanningInput{Name: row.Name, Form: contract.PlanningSealed, SealedInput: row.Sealed}
		if row.Retained != nil {
			input.Form, input.SealedInput = contract.PlanningRetained, nil
			input.Retained = contract.RetainedSecretInput{Incarnation: row.Retained.Incarnation, Material: row.Retained.Material}
		}
		inputs = append(inputs, input)
	}
	return inputs
}

func configurationPlanningSource(pair *configuration.Pair, model *configuration.Model) contract.PlanningSourcePair {
	if pair == nil || pair.Editable == nil || pair.Generated == nil || model == nil {
		return contract.PlanningSourcePair{}
	}
	return contract.PlanningSourcePair{FileIdentity: model.FileID, EditableDigest: contract.ID(pair.Editable.Digest()), GeneratedDigest: contract.ID(pair.Generated.Digest()),
		EditableLength: uint64(pair.Editable.Size()), GeneratedLength: uint64(pair.Generated.Size())}
}

func configurationPlanningConfig(model *configuration.Model, reader ReaderConfig) (PlanningConfig, error) {
	binding, err := configurationApplyBinding(model.Provider, model.Authority.Encryption)
	if err != nil {
		return PlanningConfig{}, err
	}
	basis, descriptor, err := configurationPublicBasis(model)
	if err != nil {
		return PlanningConfig{}, err
	}
	control, err := basis.ControlCore(model.DomainID, descriptor)
	if err != nil {
		return PlanningConfig{}, err
	}
	actual, err := contract.EncodeKMSBinding(binding)
	if err != nil {
		return PlanningConfig{}, err
	}
	expected, err := contract.EncodeKMSBinding(control.AuthorityKMSBinding)
	if err != nil || !bytes.Equal(actual, expected) {
		return PlanningConfig{}, core.ErrLocalAuthorityAdmission
	}
	route := contract.Hash(append([]byte("enkv/planning/authority-credential-route/v1\x00"), model.DomainID[:]...))
	return selectConfigurationPlanningConfig(model.Provider, reader, binding, route)
}

// PlanConfigurationFiles captures only the named absolute paths. It performs no
// source write and releases captured images after private work has joined.
func PlanConfigurationFiles(ctx context.Context, requestID contract.ID, trustedPath string, trustedFormat configuration.Format,
	candidatePath string, candidateFormat configuration.Format, options contract.PlanningOptions) (out ConfigurationPlanningResult) {
	return planConfigurationFiles(ctx, requestID, trustedPath, trustedFormat, candidatePath, candidateFormat, options, nil, NewDefaultPlanning)
}

func planConfigurationFiles(ctx context.Context, requestID contract.ID, trustedPath string, trustedFormat configuration.Format, candidatePath string, candidateFormat configuration.Format, options contract.PlanningOptions, factory privatecrypto.PlanningDisplayFactory, open func(context.Context, PlanningConfig) (*core.InstalledPlanning, error)) (out ConfigurationPlanningResult) {
	defer func() { finishPublicationPlanningRequest(&out, options.Publish) }()
	correlation, err := newConfigurationComparisonResult(requestID, trustedFormat)
	if err != nil {
		return configurationPlanningResult(correlation)
	}
	defer func() { finishConfigurationPlanning(&out, correlation) }()
	q := correlation.PreAdmission
	q.Stage = "capture"
	trusted, err := configuration.Capture(ctx, trustedPath, trustedFormat)
	if err != nil {
		return configurationPlanningFailure(ctx, requestID, contract.ID{}, "trusted", err)
	}
	var candidate *configuration.Pair
	defer func() {
		out = configurationPlanningCleanup(ctx, requestID, out, errors.Join(candidate.Close(), trusted.Close()))
	}()
	if candidatePath != "" {
		q.Format = configurationSourceFormat(candidateFormat)
		candidate, err = configuration.Capture(ctx, candidatePath, candidateFormat)
		if err != nil {
			baseline, baselineErr := configuration.Parse(ctx, trusted)
			if baselineErr != nil {
				q.Stage, q.Format = "parse", configurationSourceFormat(trustedFormat)
				return configurationPlanningFailure(ctx, requestID, contract.ID{}, "trusted", baselineErr)
			}
			return configurationPlanningFailure(ctx, requestID, baseline.DomainID, "candidate", err)
		}
	}
	q.Format = configurationSourceFormat(trustedFormat)
	return planConfigurationWithIdentity(ctx, requestID, trusted, candidate, options, factory, open, correlation)
}

func configurationPlanningFailure(ctx context.Context, requestID, domain contract.ID, source string, err error) ConfigurationPlanningResult {
	return configurationPlanningResult(configurationComparisonFailure(ctx, requestID, domain, source, err))
}

func configurationPlanningResult(public ConfigurationComparisonResult) ConfigurationPlanningResult {
	public.Context.Operation = contract.PlanningOperation
	public.EvidenceLimit = contract.PlanningEvidenceLimit
	return ConfigurationPlanningResult{SourceFailure: public.SourceFailure, PlanningResult: core.PlanningResult{PreAdmission: public.PreAdmission, Result: public.Result, Context: public.Context, StateResult: public.StateResult,
		PlanningPayload: contract.PlanningPayload{ComparisonPayload: public.ComparisonPayload, PrivateComplete: false, DisplayDelivery: contract.PlanningNotRequested}}, InstallationRequirements: public.InstallationRequirements}
}

func finishConfigurationPlanning(out *ConfigurationPlanningResult, correlation ConfigurationComparisonResult) {
	if out.InstallationRequirements.Differences == nil {
		out.InstallationRequirements.Differences = []InstallationRequirementDifference{}
	}
	if out.Context.OperationID.IsZero() {
		out.Context.OperationID, out.PreAdmission = correlation.Context.OperationID, correlation.PreAdmission
	}
	out.Context.Operation = contract.PlanningOperation
	out.EvidenceLimit = contract.PlanningEvidenceLimit
	if out.PreAdmission != nil && len(out.Diagnostics) != 0 {
		out.PreAdmission.Code = string(out.Diagnostics[0].Reason)
	}
}

// DisplayConfiguration requires an explicitly supplied private sink factory.
func DisplayConfiguration(ctx context.Context, requestID contract.ID, trusted, candidate *configuration.Pair, names []string, factory privatecrypto.PlanningDisplayFactory, previewOptions ...contract.ComparisonOptions) ConfigurationPlanningResult {
	options := planningDisplayOptions(names, factory)
	for _, preview := range previewOptions {
		options.Publish = options.Publish || preview.Publish
	}
	if len(previewOptions) > 1 {
		options.Purpose = 0
	}
	return planConfiguration(ctx, requestID, trusted, candidate, options, factory, NewDefaultPlanning)
}

// DisplayConfigurationFiles captures and releases the sources after the same
// joined planning operation used by equality-only file planning.
func DisplayConfigurationFiles(ctx context.Context, requestID contract.ID, trustedPath string, trustedFormat configuration.Format, candidatePath string, candidateFormat configuration.Format, names []string, factory privatecrypto.PlanningDisplayFactory, previewOptions ...contract.ComparisonOptions) ConfigurationPlanningResult {
	options := planningDisplayOptions(names, factory)
	for _, preview := range previewOptions {
		options.Publish = options.Publish || preview.Publish
	}
	if len(previewOptions) > 1 {
		options.Purpose = 0
	}
	return planConfigurationFiles(ctx, requestID, trustedPath, trustedFormat, candidatePath, candidateFormat, options, factory, NewDefaultPlanning)
}

func planningDisplayOptions(names []string, factory privatecrypto.PlanningDisplayFactory) contract.PlanningOptions {
	names = slices.Clone(names)
	for i := range names {
		names[i] = strings.Clone(names[i])
	}
	options := contract.PlanningOptions{Purpose: contract.PlanningDisplay, SelectedNames: names}
	if factory != nil {
		options.SinkID = factory.Identity()
	}
	return options
}

func configurationPlanningCleanup(ctx context.Context, requestID contract.ID, out ConfigurationPlanningResult, closeErr error) ConfigurationPlanningResult {
	if closeErr == nil {
		return out
	}
	failure := configurationPlanningResult(configurationComparisonUnavailable(ctx, requestID, out.Context.ExpectedDomain, "local-image"))
	cleanupDiagnostics, cleanupComplete := failure.Diagnostics, failure.DiagnosticsComplete
	failure.PlanningPayload = out.PlanningPayload
	failure.InstallationRequirements = out.InstallationRequirements
	failure.SourceFailure = out.SourceFailure
	failure.Verdict = contract.ComparisonUnable
	appendComparisonCleanupDiagnostics(&failure.ComparisonPayload, cleanupDiagnostics, cleanupComplete)
	switch out.StateResult {
	case contract.ReaderRefused, contract.ReaderPositiveDefect, contract.ReaderProfileBlocked:
		failure.StateResult, failure.Result = out.StateResult, out.Result
	}
	failure.Context, failure.PreAdmission = out.Context, out.PreAdmission
	if failure.PreAdmission != nil {
		failure.PreAdmission.Stage = "local-cleanup"
	}
	return failure
}

func finishPublicationPlanningRequest(out *ConfigurationPlanningResult, publish bool) {
	if !publish {
		return
	}
	out.PublicationRequested = true
	if out.Publication == nil {
		reason := out.Result.Reason
		if reason == core.NoReason {
			reason = core.AdmissionInvalid
		}
		out.Publication = &contract.PublicationPreview{ReasonCode: uint8(reason)}
	}
}

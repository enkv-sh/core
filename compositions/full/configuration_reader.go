package compositionfull

import (
	"context"
	"errors"
	"strings"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	enkvcrypto "enkv.sh/crypto"
)

// CompareConfiguration uses an explicitly trusted captured pair for verification
// and service construction. An optional independently captured candidate supplies
// desired public fields only. Both pairs remain borrowed until return. The caller
// must not mutate or close either pair while this operation runs.
func CompareConfiguration(ctx context.Context, requestID contract.ID, trusted, candidate *configuration.Pair, options ...contract.ComparisonOptions) ConfigurationComparisonResult {
	return compareConfiguration(ctx, requestID, trusted, candidate, NewDefaultReader, options...)
}

func compareConfiguration(ctx context.Context, requestID contract.ID, trusted, candidate *configuration.Pair,
	open func(context.Context, ReaderConfig) (*core.ReaderEngine, error), options ...contract.ComparisonOptions) (out ConfigurationComparisonResult) {
	defer func() { finishPublicationComparisonRequest(&out, options) }()
	var format configuration.Format
	if trusted != nil {
		format = trusted.Format
	}
	correlation, err := newConfigurationComparisonResult(requestID, format)
	if err != nil {
		return correlation
	}
	return compareConfigurationWithIdentity(ctx, requestID, trusted, candidate, open, configurationNormalizationValidation, correlation, options...)
}

func newConfigurationComparisonResult(requestID contract.ID, format configuration.Format) (ConfigurationComparisonResult, error) {
	out, err := NewComparisonRefusal(format)
	out.Context.RequestID = requestID
	if out.PreAdmission != nil {
		out.PreAdmission.RequestNonce = requestID
	}
	return out, err
}

type configurationSourceValidator func(context.Context, *configuration.Pair, *configuration.Pair, *configuration.Model, bool) (core.PublicConfigurationValidation, func(context.Context, core.PublicationPolicyActionInput) (uint8, error), *core.PublicConfigurationValidator, error)

func compareConfigurationWithIdentity(ctx context.Context, requestID contract.ID, trusted, candidate *configuration.Pair,
	open func(context.Context, ReaderConfig) (*core.ReaderEngine, error), validateSource configurationSourceValidator, correlation ConfigurationComparisonResult, options ...contract.ComparisonOptions) (out ConfigurationComparisonResult) {
	defer func() { finishPublicationComparisonRequest(&out, options) }()
	if len(options) > 1 {
		return configurationComparisonFailure(ctx, requestID, contract.ID{}, "trusted", nil)
	}
	defer func() { finishConfigurationComparison(&out, correlation) }()
	q := correlation.PreAdmission
	q.Stage = "parse"
	baseline, err := configuration.Parse(ctx, trusted)
	if err != nil {
		return configurationComparisonFailure(ctx, requestID, contract.ID{}, "trusted", err)
	}
	if !baseline.Resolved {
		return configurationComparisonFailure(ctx, requestID, baseline.DomainID, "trusted", &configuration.Diagnostic{Field: "generated", Reason: "restore-exact-generated-file"})
	}
	desired := baseline
	if candidate != nil {
		q.Format = configurationSourceFormat(candidate.Format)
		desired, err = configuration.Parse(ctx, candidate)
		if err != nil {
			return configurationComparisonFailure(ctx, requestID, baseline.DomainID, "candidate", err)
		}
	}
	requirements := compareConfigurationRequirements(baseline, desired)
	defer func() { out.InstallationRequirements = requirements }()
	if !desired.Resolved {
		return configurationComparisonFailure(ctx, requestID, baseline.DomainID, "candidate", &configuration.Diagnostic{Field: "generated", Reason: "restore-exact-generated-file"})
	}
	q.Format = configurationSourceFormat(trusted.Format)
	q.Stage = "public-basis"
	installed, err := configurationReaderConfig(baseline)
	if err != nil {
		return configurationComparisonFailure(ctx, requestID, baseline.DomainID, "trusted", err)
	}
	q.Stage = "context"
	if ctx == nil || ctx.Err() != nil || requestID.IsZero() || open == nil {
		return configurationComparisonFailure(ctx, requestID, baseline.DomainID, "trusted", nil)
	}
	if deadline, finite := ctx.Deadline(); !finite || !time.Now().Before(deadline) {
		return configurationComparisonFailure(ctx, requestID, baseline.DomainID, "trusted", context.DeadlineExceeded)
	}
	q.Stage = "public-configuration"
	baselineValidation, selectPolicy, routes, err := validateSource(ctx, trusted, trusted, baseline, candidate == nil)
	if err != nil {
		return configurationComparisonFailure(ctx, requestID, baseline.DomainID, "trusted", err)
	}
	validations := []core.PublicConfigurationValidation{baselineValidation}
	valid := baselineValidation.Valid && baselineValidation.Complete && baselineValidation.DiagnosticsComplete
	if candidate != nil {
		candidateValidation, candidateSelector, candidateRoutes, err := validateSource(ctx, trusted, candidate, desired, true)
		if err != nil {
			return configurationComparisonFailure(ctx, requestID, baseline.DomainID, "candidate", err)
		}
		selectPolicy, routes = candidateSelector, candidateRoutes
		validations = append(validations, candidateValidation)
		valid = valid && candidateValidation.Valid && candidateValidation.Complete && candidateValidation.DiagnosticsComplete
	}
	if !valid {
		if candidate != nil && candidate.Format != trusted.Format {
			q.Format = ""
		}
		return ConfigurationComparisonResult{PublicComparisonResult: core.RefusePublicComparisonSource(requestID, baseline.DomainID, validations...)}
	}
	q.Stage = "construction"
	installed.SelectPolicyAction = selectPolicy
	installed.checkedRoutes = routes
	reader, err := open(ctx, installed)
	if err != nil || reader == nil {
		return configurationComparisonUnavailable(ctx, requestID, baseline.DomainID, "trusted")
	}
	defer reader.Close()
	input := desired.Public
	beforeNames, afterNames := configurationRecipientNames(baseline), configurationRecipientNames(desired)
	if desired != baseline {
		releaseConfigurationSource(desired)
	}
	releaseConfigurationSource(baseline)
	q.Stage = "compare"
	result := ConfigurationComparisonResult{PublicComparisonResult: reader.Compare(ctx, requestID, input, options...)}
	addConfigurationRecipientNames(&result.ComparisonPayload, beforeNames, afterNames)
	return result
}

// CompareConfigurationFiles captures only the explicitly selected absolute paths.
// Capture owns private temporary images; this operation has no source writer.
func CompareConfigurationFiles(ctx context.Context, requestID contract.ID, trustedPath string, trustedFormat configuration.Format,
	candidatePath string, candidateFormat configuration.Format, options ...contract.ComparisonOptions) (out ConfigurationComparisonResult) {
	defer func() { finishPublicationComparisonRequest(&out, options) }()
	correlation, err := newConfigurationComparisonResult(requestID, trustedFormat)
	if err != nil {
		return correlation
	}
	defer func() { finishConfigurationComparison(&out, correlation) }()
	if len(options) > 1 {
		return configurationComparisonFailure(ctx, requestID, contract.ID{}, "trusted", nil)
	}
	q := correlation.PreAdmission
	q.Stage = "capture"
	trusted, err := configuration.Capture(ctx, trustedPath, trustedFormat)
	if err != nil {
		return configurationComparisonFailure(ctx, requestID, contract.ID{}, "trusted", err)
	}
	var candidate *configuration.Pair
	defer func() { out = closeConfigurationComparison(ctx, requestID, out, candidate, trusted) }()
	if candidatePath != "" {
		q.Format = configurationSourceFormat(candidateFormat)
		candidate, err = configuration.Capture(ctx, candidatePath, candidateFormat)
		if err != nil {
			var domain contract.ID
			baseline, baselineErr := configuration.Parse(ctx, trusted)
			if baselineErr != nil {
				q.Stage, q.Format = "parse", configurationSourceFormat(trustedFormat)
				result := configurationComparisonFailure(ctx, requestID, domain, "trusted", baselineErr)
				finishConfigurationComparison(&result, correlation)
				return result
			}
			domain = baseline.DomainID
			result := configurationComparisonFailure(ctx, requestID, domain, "candidate", err)
			finishConfigurationComparison(&result, correlation)
			return result
		}
	}
	q.Format = configurationSourceFormat(trustedFormat)
	result := compareConfigurationWithIdentity(ctx, requestID, trusted, candidate, NewDefaultReader, configurationNormalizationValidation, correlation, options...)
	return result
}

func closeConfigurationComparison(ctx context.Context, requestID contract.ID, result ConfigurationComparisonResult, pairs ...*configuration.Pair) ConfigurationComparisonResult {
	var err error
	for _, pair := range pairs {
		if pair != nil {
			err = errors.Join(err, pair.Close())
		}
	}
	if err != nil {
		failure := configurationComparisonUnavailable(ctx, requestID, result.Context.ExpectedDomain, "local-image")
		cleanupDiagnostics, cleanupComplete := failure.Diagnostics, failure.DiagnosticsComplete
		failure.ComparisonPayload = result.ComparisonPayload
		appendComparisonCleanupDiagnostics(&failure.ComparisonPayload, cleanupDiagnostics, cleanupComplete)
		failure.Verdict = contract.ComparisonUnable
		failure.Context, failure.PreAdmission = result.Context, result.PreAdmission
		failure.InstallationRequirements = result.InstallationRequirements
		failure.SourceFailure = result.SourceFailure
		switch result.StateResult {
		case contract.ReaderRefused, contract.ReaderPositiveDefect, contract.ReaderProfileBlocked:
			failure.StateResult, failure.Result = result.StateResult, result.Result
		}
		if failure.PreAdmission != nil {
			failure.PreAdmission.Stage = "local-cleanup"
		}
		return failure
	}
	return result
}

func appendComparisonCleanupDiagnostics(payload *contract.ComparisonPayload, rows []contract.Diagnostic, complete bool) {
	payload.DiagnosticsComplete = payload.DiagnosticsComplete && complete
	capacity := min(len(payload.Diagnostics)+len(rows), contract.MaxPublicDiagnostics-len(payload.Changes))
	if capacity < len(payload.Diagnostics) {
		payload.DiagnosticsComplete = false
		return
	}
	owned := make([]contract.Diagnostic, len(payload.Diagnostics), capacity)
	copy(owned, payload.Diagnostics)
	payload.Diagnostics = owned
	for _, row := range rows {
		if len(payload.Diagnostics)+len(payload.Changes) == contract.MaxPublicDiagnostics {
			payload.DiagnosticsComplete = false
			if len(payload.Diagnostics) != 0 {
				payload.Diagnostics[len(payload.Diagnostics)-1] = row
				continue
			}
			at := len(payload.Changes) - 1
			payload.Changes[at] = contract.ComparisonChange{}
			payload.Changes = payload.Changes[:at]
		}
		payload.Diagnostics = append(payload.Diagnostics, row)
	}
}

func finishConfigurationComparison(out *ConfigurationComparisonResult, correlation ConfigurationComparisonResult) {
	if out.InstallationRequirements.Differences == nil {
		out.InstallationRequirements.Differences = []InstallationRequirementDifference{}
	}
	if out.Context.OperationID.IsZero() {
		out.Context.OperationID, out.PreAdmission = correlation.Context.OperationID, correlation.PreAdmission
	}
	if out.PreAdmission != nil && len(out.Diagnostics) != 0 {
		out.PreAdmission.Code = string(out.Diagnostics[0].Reason)
	}
}

func configurationPublicBasis(m *configuration.Model) (core.PublicBasis, contract.Descriptor, error) {
	basis := core.PublicBasis{Descriptor: m.Basis.Descriptor, Control: m.Basis.Control, Selection: m.Basis.Selection,
		SigningAnchor: m.Basis.SigningAnchor, StoreConfiguration: m.Basis.StoreConfiguration, HEAD: m.Basis.HEAD, Root: m.Basis.Root, RecipientPages: m.Basis.RecipientPages}
	for _, row := range m.Basis.Enrollment {
		basis.Enrollment = append(basis.Enrollment, core.PublicEnrollment{RecipientID: row.ID, Status: row.Status, DisplayName: row.DisplayName})
	}
	storeID, err := contract.StoreConfigurationID(contract.StoreConfiguration{Provider: m.Provider, ConstructionProfile: contract.StoreConstructionProfile,
		DomainID: m.DomainID, Region: m.Store.Region, Bucket: m.Store.Bucket, PrefixBeforeHEAD: m.Store.PrefixBeforeHEAD, ExpectedOwner: m.Store.ExpectedOwner})
	if err != nil {
		return core.PublicBasis{}, contract.Descriptor{}, err
	}
	descriptor := contract.Descriptor{Family: m.Provider, Identity: storeID, Prefix: m.Store.PrefixBeforeHEAD, HeadKey: m.Store.PrefixBeforeHEAD + "/HEAD"}
	if len(basis.Descriptor) != 0 {
		value, err := contract.DecodeGenesisDescriptorCore(basis.Descriptor)
		if err != nil || value.StoreID != storeID {
			return core.PublicBasis{}, contract.Descriptor{}, core.ErrLocalAuthorityAdmission
		}
		descriptor.Coordinate, descriptor.NonBody = value.CoordinateID, value.NonBodyID
	} else if len(basis.HEAD) != 0 {
		value, err := format.DecodeHead(basis.HEAD)
		if err != nil || value.Core.Store != storeID {
			return core.PublicBasis{}, contract.Descriptor{}, core.ErrLocalAuthorityAdmission
		}
		descriptor.Coordinate, descriptor.NonBody = value.Core.Coordinate, value.Core.NonBody
	} else {
		value, err := contract.DecodeControlCore(basis.Control)
		if err != nil || value.StoreID != storeID {
			return core.PublicBasis{}, contract.Descriptor{}, core.ErrLocalAuthorityAdmission
		}
		descriptor.Coordinate, descriptor.NonBody = value.CoordinateID, value.NonBodyID
	}
	if _, err := basis.ControlCore(m.DomainID, descriptor); err != nil {
		return core.PublicBasis{}, contract.Descriptor{}, err
	}
	return basis, descriptor, nil
}

func validateInstalledConfiguration(ctx context.Context, input contract.PublicConfiguration) core.PublicConfigurationValidation {
	return core.NewPublicConfigurationValidator(nil).Validate(ctx, input)
}

func configurationReaderConfig(m *configuration.Model) (ReaderConfig, error) {
	basis, descriptor, err := configurationPublicBasis(m)
	if err != nil {
		return ReaderConfig{}, err
	}
	storeID := descriptor.Identity
	route := contract.Hash(append([]byte("enkv/reader/default-credential-route/v1\x00"), storeID[:]...))
	return selectConfigurationReader(m, basis, descriptor, route)
}

func configurationComparisonFailure(ctx context.Context, requestID, domain contract.ID, source string, err error) ConfigurationComparisonResult {
	reason := contract.ReasonInvalidInput
	if configurationPluginUnavailable(err) {
		reason = contract.ReasonEvidenceUnavailable
	}
	var location *contract.SourceLocation
	var diagnostic *configuration.Diagnostic
	if errors.As(err, &diagnostic) {
		if diagnostic.Generated {
			source += ".generated"
		}
		switch diagnostic.Reason {
		case "read-failed":
			reason = contract.ReasonEvidenceUnavailable
		case "restore-exact-generated-file", "missing-prepared-recipient", "missing-prepared-secret", "missing-required-field":
			reason = contract.ReasonMissingRequiredField
		case "duplicate-key":
			reason = contract.ReasonDuplicateKey
		case "unsupported-schema":
			reason = contract.ReasonUnsupportedSchema
		case "invalid-utf8", "invalid-unicode":
			reason = contract.ReasonInvalidUTF8
		case "expired":
			reason = contract.ReasonExpired
		default:
			if strings.Contains(diagnostic.Reason, "limit") {
				reason = contract.ReasonLimitExceeded
			}
		}
		if !diagnostic.Context && diagnostic.Line != 0 && diagnostic.Column != 0 {
			location = &contract.SourceLocation{SourceID: source, Line: diagnostic.Line, Column: diagnostic.Column}
		}
	} else if errors.Is(err, core.ErrLocalAuthorityAdmission) {
		reason = contract.ReasonTrustBasisInvalid
	}
	var contextErr error
	if ctx != nil {
		contextErr = ctx.Err()
	}
	if contextErr != nil {
		reason = contract.ReasonCancelled
		if errors.Is(contextErr, context.DeadlineExceeded) {
			reason = contract.ReasonExpired
		}
	} else if errors.Is(err, context.DeadlineExceeded) {
		reason = contract.ReasonExpired
	} else if errors.Is(err, context.Canceled) {
		reason = contract.ReasonCancelled
	}
	result := ConfigurationComparisonResult{SourceFailure: configurationSourceFailure(strings.TrimSuffix(source, ".generated"), err), PublicComparisonResult: core.PublicComparisonResult{Result: core.Result{Outcome: core.AdmissionRefused, Reason: core.AdmissionInvalid},
		Context: core.ReaderOperationContext{Operation: contract.ReaderCompareOperation, RequestID: requestID, ExpectedDomain: domain}, StateResult: contract.ReaderRefused,
		ComparisonPayload: contract.ComparisonPayload{Verdict: contract.ComparisonUnable, DiagnosticsComplete: true, EvidenceLimit: contract.ComparisonEvidenceLimit,
			Diagnostics: []contract.Diagnostic{{Subject: contract.DiagnosticSubject{Kind: contract.SubjectConfiguration}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: reason, SourceLocation: location}}}}, InstallationRequirements: InstallationRequirementComparison{Differences: []InstallationRequirementDifference{}}}
	if reason == contract.ReasonEvidenceUnavailable {
		result.StateResult = contract.ReaderUnavailable
		result.Result = core.Result{Outcome: core.EvidenceUnavailable, Reason: core.ReadUnavailable}
	}
	for _, family := range []contract.ComparisonFieldFamily{contract.ScopeEntries, contract.ScopePlainValues, contract.ScopeSecretSettings, contract.ScopeMemberships, contract.ScopeRecipients,
		contract.ScopeEncryption, contract.ScopeGenerated, contract.ScopeOutputs, contract.ScopeRouting, contract.ScopeDomainStore, contract.ScopeAuthorityRecovery, contract.ScopeCompatibilityProfiles} {
		result.CheckedScope = append(result.CheckedScope, contract.ComparisonScope{Family: family, Status: contract.ScopeUnchecked})
	}
	return result
}

func configurationComparisonUnavailable(ctx context.Context, requestID, domain contract.ID, source string) ConfigurationComparisonResult {
	result := configurationComparisonFailure(ctx, requestID, domain, source, nil)
	if ctx == nil || ctx.Err() == nil {
		result.StateResult = contract.ReaderUnavailable
		result.Result = core.Result{Outcome: core.EvidenceUnavailable, Reason: core.ReadUnavailable}
		result.Diagnostics[0].Reason = contract.ReasonEvidenceUnavailable
	}
	return result
}

func finishPublicationComparisonRequest(out *ConfigurationComparisonResult, options []contract.ComparisonOptions) {
	for _, option := range options {
		if option.Publish {
			out.PublicationRequested = true
			if out.Publication == nil {
				reason := out.Result.Reason
				if reason == core.NoReason {
					reason = core.AdmissionInvalid
				}
				out.Publication = &contract.PublicationPreview{ReasonCode: uint8(reason)}
			}
			return
		}
	}
}

func releaseConfigurationSource(model *configuration.Model) {
	if model == nil {
		return
	}
	releaseConfigurationBasis(model)
	*model = configuration.Model{}
}

func releaseConfigurationBasis(model *configuration.Model) {
	basis := &model.Basis
	for _, body := range [][]byte{basis.Descriptor, basis.Control, basis.Selection, basis.SigningAnchor, basis.StoreConfiguration, basis.HEAD, basis.Root} {
		clear(body)
	}
	for _, page := range basis.RecipientPages {
		clear(page)
	}
	model.Basis = configuration.Basis{}
}

func configurationPolicyActionSelector(plugins *configurationInstalledPlugins, model *configuration.Model) func(context.Context, core.PublicationPolicyActionInput) (uint8, error) {
	type selectedOutput struct{ plugin, config string }
	outputs := make(map[string]selectedOutput, len(model.Outputs))
	for _, binding := range model.Outputs {
		outputs[binding.DestinationID] = selectedOutput{strings.Clone(binding.Plugin), strings.Clone(binding.Binding.Destination.ConfigContractID)}
	}
	return func(ctx context.Context, in core.PublicationPolicyActionInput) (uint8, error) {
		selected, present := outputs[in.DestinationID]
		if !present || selected.plugin == "" || selected.config != in.ConfigContractID {
			return 0, ErrCell
		}
		path, installed, err := configurationOutputArtifact(plugins, selected.plugin)
		if err != nil {
			return 0, err
		}
		action, err := enkvcrypto.SelectPublicationPolicyAction(ctx, path, installed, enkvcrypto.PublicationPolicyActionInput{DomainID: in.DomainID, Target: in.Target,
			HasPreviousPolicyDigest: in.HasPreviousPolicyDigest, PreviousPolicyDigest: in.PreviousPolicyDigest, Deadline: in.Deadline})
		return uint8(action), err
	}
}

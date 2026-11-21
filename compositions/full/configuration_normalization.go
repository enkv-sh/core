package compositionfull

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/compositions/full/plugininstallation"
	"enkv.sh/compositions/generatorhost"
	"enkv.sh/compositions/outputhost"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	generator "enkv.sh/sdk/protocols/generator"
	output "enkv.sh/sdk/protocols/output"
)

// configurationNormalizePlugins retains source settings and installs their exact
// canonical meaning. Only trustedPair selects the local installation scope.
func configurationNormalizePlugins(ctx context.Context, trustedPair, sourcePair *configuration.Pair, model *configuration.Model) (*configurationInstalledPlugins, *core.PublicConfigurationValidator, error) {
	return configurationNormalizePluginsWithOutputValidator(ctx, trustedPair, configurationNormalizationSourceCheck(trustedPair, sourcePair), model, true, nil, outputhost.NewPublicValidator)
}

func configurationNormalizationSourceCheck(trusted, source *configuration.Pair) func(context.Context) error {
	if trusted == nil || source == nil {
		return nil
	}
	return func(ctx context.Context) error {
		if err := trusted.CheckUnchanged(ctx); err != nil {
			return err
		}
		if source != trusted {
			return source.CheckUnchanged(ctx)
		}
		return nil
	}
}

func configurationNormalizePluginsWithOutputValidator(ctx context.Context, trustedPair *configuration.Pair, checkSource func(context.Context) error, model *configuration.Model, proposed bool, plugins *configurationInstalledPlugins,
	newOutputValidator func(context.Context, string, *outputhost.Installation) (*outputhost.PublicValidator, error)) (*configurationInstalledPlugins, *core.PublicConfigurationValidator, error) {
	if ctx == nil || model == nil || trustedPair == nil || checkSource == nil {
		return nil, nil, ErrCell
	}
	if !model.Resolved {
		return nil, nil, &configuration.Diagnostic{Field: "generated", Reason: "restore-exact-generated-file"}
	}
	if _, err := configurationPassiveDeadline(ctx); err != nil {
		return nil, nil, err
	}
	if err := checkSource(ctx); err != nil {
		return nil, nil, err
	}
	requirements, err := configurationNormalizationRequirements(model)
	if err != nil {
		return nil, nil, err
	}
	if len(requirements) > 0 && plugins == nil {
		plugins, _, err = configurationCapturePluginsWithSourceCheck(ctx, trustedPair, requirements, plugininstallation.Ordinary, checkSource)
		if err != nil {
			return nil, nil, errors.Join(plugininstallation.ErrInstallation, err)
		}
	}
	type generatorNormalizer struct {
		name      string
		validator *generatorhost.PublicValidator
		config    generator.ID
	}
	generators := make([]generatorNormalizer, 0, len(requirements))
	type outputNormalizer struct {
		name      string
		validator *outputhost.PublicValidator
	}
	outputs := make([]outputNormalizer, 0, len(requirements))
	for i := range model.Entries {
		g := model.Entries[i].Generated
		if g == nil || g.Plugin == "" {
			continue
		}
		index := slices.IndexFunc(generators, func(row generatorNormalizer) bool { return row.name == g.Plugin })
		cached := generatorNormalizer{name: g.Plugin}
		if index >= 0 {
			cached = generators[index]
		}
		if cached.validator == nil {
			selected, ok := plugins.lookup(g.Plugin)
			if !ok {
				return nil, nil, errors.Join(plugininstallation.ErrInstallation, plugininstallation.ErrMissing)
			}
			metadata, err := selected.Metadata()
			if err != nil {
				return nil, nil, errors.Join(plugininstallation.ErrInstallation, err)
			}
			installed, err := generatorhost.NewInstallation(metadata, selected.DependencyBytes())
			if err != nil {
				return nil, nil, errors.Join(plugininstallation.ErrInstallation, err)
			}
			cached.validator, err = generatorhost.NewPublicValidator(ctx, selected.Executable(), installed)
			if err != nil {
				return nil, nil, errors.Join(plugininstallation.ErrInstallation, err)
			}
			cached.config = generator.ID(installed.Artifact().ConfigContractID)
			generators = append(generators, cached)
		}
		if err := checkSource(ctx); err != nil {
			return nil, nil, err
		}
		if err := configurationNormalizeGenerator(ctx, cached.validator, cached.config, g); err != nil {
			return nil, nil, err
		}
		if err := checkSource(ctx); err != nil {
			return nil, nil, err
		}
	}
	type destinationNormalizer struct {
		id        string
		validator *outputhost.PublicValidator
	}
	byDestination := make([]destinationNormalizer, 0, len(model.Outputs))
	for i := range model.Outputs {
		binding := &model.Outputs[i]
		if binding.Plugin == "" {
			continue
		}
		index := slices.IndexFunc(outputs, func(row outputNormalizer) bool { return row.name == binding.Plugin })
		var validator *outputhost.PublicValidator
		if index >= 0 {
			validator = outputs[index].validator
		}
		if validator == nil {
			path, installed, err := configurationOutputArtifact(plugins, binding.Plugin)
			if err != nil {
				return nil, nil, errors.Join(plugininstallation.ErrInstallation, err)
			}
			validator, err = newOutputValidator(ctx, path, installed)
			if err != nil {
				return nil, nil, errors.Join(plugininstallation.ErrInstallation, err)
			}
			outputs = append(outputs, outputNormalizer{name: binding.Plugin, validator: validator})
		}
		if err := checkSource(ctx); err != nil {
			return nil, nil, err
		}
		deadline, err := configurationPassiveDeadline(ctx)
		if err != nil {
			return nil, nil, err
		}
		if binding.Settings != nil {
			result, err := validator.Normalize(ctx, output.NormalizeRequest{Schema: 1, DeadlineUnixMillis: deadline, Settings: binding.Settings})
			if err != nil {
				return nil, nil, err
			}
			binding.Binding.Destination = configurationOutputDestination(result.Destination)
		} else {
			_, err := validator.ValidateCanonical(ctx, output.CanonicalRequest{Schema: 1, DeadlineUnixMillis: deadline, Destination: configurationProtocolDestination(binding.Binding.Destination)})
			if err != nil {
				return nil, nil, err
			}
		}
		byDestination = append(byDestination, destinationNormalizer{id: binding.DestinationID, validator: validator})
		if err := checkSource(ctx); err != nil {
			return nil, nil, err
		}
	}
	interpret := core.PublicOutputInterpreter(func(callCtx context.Context, destinationID string, destination contract.OutputDestination, name string, encoding uint8) (target contract.OutputTarget, resultErr error) {
		defer func() {
			if configurationPluginUnavailable(resultErr) {
				resultErr = errors.Join(core.ErrPublicOutputUnavailable, resultErr)
			}
		}()
		index := slices.IndexFunc(byDestination, func(row destinationNormalizer) bool { return row.id == destinationID })
		if index < 0 {
			return contract.OutputTarget{}, outputhost.ErrArtifactMissing
		}
		if err := checkSource(callCtx); err != nil {
			return contract.OutputTarget{}, err
		}
		target, err := configurationInterpretOutput(callCtx, byDestination[index].validator, destination, name, encoding)
		if err != nil {
			return contract.OutputTarget{}, err
		}
		if err := checkSource(callCtx); err != nil {
			return contract.OutputTarget{}, err
		}
		return target, nil
	})
	if len(byDestination) == 0 {
		interpret = nil
	}
	if err := configurationProjectNormalized(model); err != nil {
		return nil, nil, err
	}
	validator := core.NewPublicConfigurationValidator(interpret)
	check := validator.Validate
	if proposed {
		check = validator.ValidateProposed
	}
	validated := check(ctx, model.Public)
	if !validated.Valid || !validated.Complete || !validated.DiagnosticsComplete {
		return nil, nil, &configurationNormalizationError{validation: validated}
	}
	model.Public = validated.Configuration
	for i := range model.Outputs {
		source := &model.Outputs[i]
		at := slices.IndexFunc(model.Public.OutputBindings.Value, func(b contract.PublicOutputBinding) bool { return b.DestinationID == source.DestinationID })
		if at < 0 {
			return nil, nil, contract.ErrRecord
		}
		source.Binding.Targets = make([]contract.NormalOutputTarget, 0, len(model.Public.OutputBindings.Value[at].Targets.Value))
		for _, target := range model.Public.OutputBindings.Value[at].Targets.Value {
			source.Binding.Targets = append(source.Binding.Targets, contract.NormalOutputTarget{Name: strings.Clone(target.EntryName), Target: configurationCanonicalTarget(target)})
		}
	}
	if err := checkSource(ctx); err != nil {
		return nil, nil, err
	}
	return plugins, validated.CheckedRouteValidator(), nil
}

func configurationInterpretOutput(ctx context.Context, validator *outputhost.PublicValidator, destination contract.OutputDestination, name string, encoding uint8) (contract.OutputTarget, error) {
	deadline, err := configurationPassiveDeadline(ctx)
	if err != nil {
		return contract.OutputTarget{}, err
	}
	result, err := validator.InterpretTarget(ctx, output.InterpretRequest{Schema: 1, DeadlineUnixMillis: deadline, Destination: configurationProtocolDestination(destination), EntryName: name, PayloadEncoding: encoding})
	if err != nil {
		return contract.OutputTarget{}, err
	}
	return configurationOutputTarget(result.Target, destination.Policy), nil
}

// Update derived fields in place so captured source locations remain attached.
func configurationProjectNormalized(model *configuration.Model) error {
	for _, entry := range model.Entries {
		if entry.Generated == nil {
			continue
		}
		at := slices.IndexFunc(model.Public.Entries.Value, func(row contract.PublicEntry) bool { return row.Name == entry.Name })
		if at < 0 || model.Public.Entries.Value[at].Generated == nil {
			return contract.ErrRecord
		}
		g := entry.Generated
		if err := configuration.ValidateGeneratorSource(g); err != nil {
			return err
		}
		intent, err := contract.InspectGeneratorIntent(g.Intent)
		if err != nil {
			return err
		}
		public := model.Public.Entries.Value[at].Generated
		public.ConfigContractID.State, public.ConfigContractID.Value = contract.PublicPresent, intent.ConfigContractID
		public.ResourceContractID.State, public.ResourceContractID.Value = contract.PublicPresent, intent.ResourceContractID
		public.LifecycleMode.State, public.LifecycleMode.Value = contract.PublicPresent, intent.LifecycleMode
		public.ContentIntent.State, public.ContentIntent.Value = contract.PublicPresent, g.Intent
		if intent.LifecycleMode == contract.GeneratorLifecycleManaged {
			retirement := contract.GeneratedRetirementManual
			if g.Retirement == "auto" {
				retirement = contract.GeneratedRetirementAuto
			}
			public.Retirement.State, public.Retirement.Value = contract.PublicPresent, retirement
			public.Completion.State, public.Completion.Value = contract.PublicPresent, contract.GeneratedCompletionAcknowledged
		} else {
			public.Retirement = contract.PublicField[uint8]{}
			public.Completion = contract.PublicField[uint8]{}
		}
	}
	for _, source := range model.Outputs {
		at := slices.IndexFunc(model.Public.OutputBindings.Value, func(row contract.PublicOutputBinding) bool { return row.DestinationID == source.DestinationID })
		if at < 0 {
			return contract.ErrRecord
		}
		model.Public.OutputBindings.Value[at].Destination.State = contract.PublicPresent
		model.Public.OutputBindings.Value[at].Destination.Value = source.Binding.Destination
	}
	return nil
}

func configurationNormalizationRequirements(model *configuration.Model) ([]plugininstallation.Requirement, error) {
	all, err := configurationPluginRequirements(model)
	if err != nil {
		return nil, err
	}
	rows := make([]plugininstallation.Requirement, 0, len(all))
	for _, row := range all {
		needed := slices.ContainsFunc(model.Entries, func(entry configuration.Entry) bool {
			return entry.Generated != nil && entry.Generated.Plugin == row.Name
		})
		if !needed {
			needed = slices.ContainsFunc(model.Outputs, func(binding configuration.OutputBinding) bool { return binding.Plugin == row.Name })
		}
		if needed {
			rows = append(rows, row)
		}
	}
	return rows, nil
}

func configurationPassiveDeadline(ctx context.Context) (uint64, error) {
	if ctx == nil {
		return 0, ErrCell
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	deadline, ok := ctx.Deadline()
	if !ok || !time.Now().Before(deadline) || deadline.UnixMilli() <= 0 {
		return 0, context.DeadlineExceeded
	}
	return uint64(deadline.UnixMilli()), nil
}

func configurationNormalizeGenerator(ctx context.Context, validator *generatorhost.PublicValidator, configID generator.ID, g *configuration.Generator) error {
	deadline, err := configurationPassiveDeadline(ctx)
	if err != nil {
		return err
	}
	if g.Settings == nil {
		request := generator.CanonicalRequest{Schema: generator.Schema, DeadlineUnixMillis: deadline, Purpose: generator.CanonicalHistorical, Intent: g.Intent}
		request.InputDigest, err = generator.CanonicalInputDigest(request)
		if err != nil {
			return err
		}
		_, err = validator.ValidateCanonical(ctx, request)
		return err
	}
	request := generator.NormalizeRequest{Schema: generator.Schema, DeadlineUnixMillis: deadline, ConfigContractID: configID, Settings: g.Settings}
	request.InputDigest, err = generator.NormalizeInputDigest(request)
	if err != nil {
		return err
	}
	result, err := validator.Normalize(ctx, request)
	if err != nil {
		return err
	}
	g.Intent = result.Intent
	return nil
}

// These boundary translations preserve canonical backing without copying.
// Their callers keep the captured model and passive result owners valid through
// validation; a type conversion does not create a new immutable owner.
func configurationOutputDestination(v output.Destination) contract.OutputDestination {
	return contract.OutputDestination{ConfigContractID: v.ConfigContractID, ServiceContractID: v.ServiceContractID, CanonicalSettings: v.CanonicalSettings, Policy: contract.OutputPolicy{ContractID: v.Policy.ContractID, Data: v.Policy.Data}, Capabilities: contract.OutputActionCapabilities(v.Capabilities)}
}
func configurationProtocolDestination(v contract.OutputDestination) output.Destination {
	return output.Destination{ConfigContractID: v.ConfigContractID, ServiceContractID: v.ServiceContractID, CanonicalSettings: v.CanonicalSettings, Policy: output.Policy{ContractID: v.Policy.ContractID, Data: v.Policy.Data}, Capabilities: output.ActionCapabilities(v.Capabilities)}
}
func configurationOutputTarget(v output.Target, policy contract.OutputPolicy) contract.OutputTarget {
	return contract.OutputTarget{ServiceContractID: v.ServiceContractID, TargetContractID: v.TargetContractID, CanonicalTarget: v.CanonicalTarget, ConsumerLocator: v.ConsumerLocator, TargetData: v.TargetData, PayloadEncoding: v.PayloadEncoding, LocatorRequiresCreation: v.LocatorRequiresCreation, Capabilities: contract.OutputActionCapabilities(v.Capabilities), CreateValueBounds: contract.OutputPayloadBounds(v.CreateValueBounds), WriteValueBounds: contract.OutputPayloadBounds(v.WriteValueBounds), Policy: contract.OutputPolicy{ContractID: policy.ContractID, Data: policy.Data}}
}
func configurationCanonicalTarget(v contract.PublicOutputTarget) contract.OutputTarget {
	return contract.OutputTarget{ServiceContractID: v.ServiceContractID.Value, TargetContractID: v.TargetContractID.Value, CanonicalTarget: v.CanonicalTarget.Value, ConsumerLocator: v.ConsumerLocator.Value, TargetData: v.TargetData.Value, PayloadEncoding: v.PayloadEncoding.Value, LocatorRequiresCreation: v.LocatorRequiresCreation.Value, Capabilities: v.Capabilities.Value, CreateValueBounds: v.CreateValueBounds.Value, WriteValueBounds: v.WriteValueBounds.Value, Policy: contract.OutputPolicy{ContractID: v.ConsumerPolicy.Value.ContractID, Data: v.ConsumerPolicy.Value.Data}}
}

type configurationNormalizationError struct {
	validation core.PublicConfigurationValidation
}

func (*configurationNormalizationError) Error() string {
	return "public configuration normalization refused"
}
func (*configurationNormalizationError) Unwrap() error { return contract.ErrRecord }

func (e *configurationNormalizationError) Is(target error) bool {
	var reason contract.DiagnosticReason
	switch target {
	case context.Canceled:
		reason = contract.ReasonCancelled
	case context.DeadlineExceeded:
		reason = contract.ReasonExpired
	default:
		return false
	}
	return slices.ContainsFunc(e.validation.Diagnostics, func(diagnostic contract.Diagnostic) bool { return diagnostic.Reason == reason })
}

func configurationNormalizationValidation(ctx context.Context, trusted, source *configuration.Pair, model *configuration.Model, proposed bool) (result core.PublicConfigurationValidation, selector func(context.Context, core.PublicationPolicyActionInput) (uint8, error), routes *core.PublicConfigurationValidator, resultErr error) {
	var scope outputhost.PublicValidationScope
	var normalizationErr error
	defer func() {
		if err := scope.Close(); err != nil {
			resultErr = errors.Join(normalizationErr, resultErr, err)
			selector, routes = nil, nil
		}
	}()
	plugins, routes, err := configurationNormalizePluginsWithOutputValidator(ctx, trusted, configurationNormalizationSourceCheck(trusted, source), model, proposed, nil, func(ctx context.Context, path string, installation *outputhost.Installation) (*outputhost.PublicValidator, error) {
		return scope.NewValidator(ctx, path, installation)
	})
	normalizationErr = err
	if err != nil {
		var invalid *configurationNormalizationError
		if errors.As(err, &invalid) {
			result := invalid.validation
			result.Configuration = contract.PublicConfiguration{}
			return result, nil, nil, nil
		}
		return core.PublicConfigurationValidation{}, nil, nil, err
	}
	return core.PublicConfigurationValidation{Valid: true, Complete: true, DiagnosticsComplete: true}, configurationPolicyActionSelector(plugins, model), routes, nil
}

func configurationPluginUnavailable(err error) bool {
	if err == nil || errors.Is(err, configuration.ErrSourceChanged) || errors.Is(err, plugininstallation.ErrSourceChanged) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var invalid *configurationNormalizationError
	if errors.As(err, &invalid) {
		return core.RefusePublicComparisonSource(contract.ID{}, contract.ID{}, invalid.validation).StateResult == contract.ReaderUnavailable
	}
	for _, unavailable := range [...]error{
		plugininstallation.ErrInstallation,
		generatorhost.ErrProcess, generatorhost.ErrArtifactMissing, generatorhost.ErrArtifactIdentity, generatorhost.ErrArtifactIncompatible, generatorhost.ErrArtifactPlatform, generatorhost.ErrArtifactUnavailable,
		outputhost.ErrProcess, outputhost.ErrArtifactMissing, outputhost.ErrArtifactIdentity, outputhost.ErrArtifactIncompatible, outputhost.ErrArtifactPlatform, outputhost.ErrArtifactUnavailable,
	} {
		if errors.Is(err, unavailable) {
			return true
		}
	}
	return false
}

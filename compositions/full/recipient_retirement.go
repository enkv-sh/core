package compositionfull

import (
	"context"
	"errors"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	enkvcrypto "enkv.sh/crypto"
)

type configurationRetirementEngine interface {
	Retire(context.Context, contract.ID) core.PublicApplyResult
	Close()
}

// RetireConfigurationRecipient authenticates one exact current recipient and
// removes its derived memberships and registry row together. The borrowed pair
// remains open and unchanged; valid pending declarations are not applied.
func RetireConfigurationRecipient(ctx context.Context, requestID contract.ID, pair *configuration.Pair, reference string, output *configuration.MaintenanceOutput) core.PublicApplyResult {
	return retireConfigurationRecipient(ctx, requestID, pair, reference, output, openConfigurationRecipientRetirement)
}

func retireConfigurationRecipient(ctx context.Context, requestID contract.ID, pair *configuration.Pair, reference string, output *configuration.MaintenanceOutput,
	open func(context.Context, *configuration.Model, core.RecipientRetirementInstallation) (configurationRetirementEngine, error)) core.PublicApplyResult {
	m, i, out, ok := configurationAccessMutationSource(ctx, requestID, pair)
	if !ok {
		return out
	}
	recipient, err := configurationRecipientReference(m, reference)
	if err != nil {
		return configurationApplyFailure(ctx, out, "declaration", err)
	}
	if err := configureMaintenanceOutput(ctx, pair, m, &i, output, configuration.MaintenanceRequest{OperationKind: contract.OperationRetireRecipientIdentity, RecipientReference: reference, RecipientID: recipient.RecipientID, BindingDigest: recipient.PublicBindingDigest}); err != nil {
		return configurationApplyFailure(ctx, out, "output", err)
	}
	if open == nil {
		return configurationApplyFailure(ctx, out, "context", nil)
	}
	engine, err := open(ctx, m, core.RecipientRetirementInstallation{AccessMutationInstallation: i, Recipient: recipient})
	if err != nil || engine == nil {
		return configurationAccessMutationUnavailable(ctx, out)
	}
	releaseConfigurationBasis(m)
	i = core.AccessMutationInstallation{}
	defer engine.Close()
	return finishConfigurationAccessMutation(ctx, engine.Retire(ctx, requestID), out, "retire")
}

// RetireConfigurationRecipientFile captures the named output before the source.
func RetireConfigurationRecipientFile(ctx context.Context, requestID contract.ID, path string, format configuration.Format, reference, outputPath string) MaintenanceCommandResult {
	return runConfigurationMaintenance(ctx, requestID, path, format, configuration.MaintenanceRequest{OperationKind: contract.OperationRetireRecipientIdentity, RecipientReference: reference}, outputPath, defaultReplacementObservationSource)
}

// RetireConfigurationSelectedRecipientFile selects an existing local recipient
// before preparing its protected successor and authenticated retirement.
func RetireConfigurationSelectedRecipientFile(ctx context.Context, requestID contract.ID, path string, format configuration.Format, selector RecipientSelector, outputPath string) MaintenanceCommandResult {
	if !selector.valid() || selector.Reference == "" && selector.ID.IsZero() {
		raw, err := newConfigurationApplyResult(requestID, format)
		return MaintenanceCommandResult{PublicApplyResult: configurationApplyFailure(ctx, raw, "declaration", errors.Join(configuration.ErrEdit, err)), Delivery: ReplacementCommandDelivery{Status: "not-attempted"}, SourceUsability: "unchecked"}
	}
	return runConfigurationMaintenance(ctx, requestID, path, format, configuration.MaintenanceRequest{OperationKind: contract.OperationRetireRecipientIdentity, RecipientReference: selector.Reference, RecipientID: selector.ID}, outputPath, defaultReplacementObservationSource)
}

func openConfigurationRecipientRetirement(ctx context.Context, m *configuration.Model, i core.RecipientRetirementInstallation) (configurationRetirementEngine, error) {
	installation, runtime, route, err := openConfigurationAccessMutation(ctx, m, i.AccessMutationInstallation)
	if err != nil {
		return nil, err
	}
	i.AdmitCustody = func(ctx context.Context, q contract.CryptoCompareRequest, control contract.ControlCore, current []contract.RecipientRecord, retiredSlot uint16, plain []contract.MembershipRow, support contract.DescriptorVector, witness *contract.GeneratedSupportTransition, revision contract.ID, before contract.MutationReceiptWindows, warningBits uint8, deadline time.Time) (*core.InstalledApplyCustody, error) {
		owner, err := enkvcrypto.NewRecipientRetirementCustody(runtime, q, control, current, retiredSlot, route, plain, support, witness, revision, before, warningBits, deadline)
		if err != nil {
			return nil, err
		}
		return &core.InstalledApplyCustody{Crypto: owner, BindReceipt: owner.BindReceipt, Close: owner.Close}, nil
	}
	i.AccessMutationInstallation = installation
	engine, err := core.NewInstalledRecipientRetirement(i)
	if err != nil {
		runtime.Close()
		return nil, err
	}
	return engine, nil
}

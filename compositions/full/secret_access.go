package compositionfull

import (
	"context"
	"time"
	"unicode/utf8"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	enkvcrypto "enkv.sh/crypto"
)

type configurationRekeyEngine interface {
	Rekey(context.Context, contract.ID) core.PublicApplyResult
	Close()
}

// RekeyConfigurationEnvelope refreshes one current secret's protection without
// applying pending declarations or running its provider generator.
func RekeyConfigurationEnvelope(ctx context.Context, requestID contract.ID, pair *configuration.Pair, name string, output *configuration.MaintenanceOutput) core.PublicApplyResult {
	return rekeyConfigurationEnvelope(ctx, requestID, pair, name, output, openConfigurationEnvelopeRekey)
}

func rekeyConfigurationEnvelope(ctx context.Context, requestID contract.ID, pair *configuration.Pair, name string, output *configuration.MaintenanceOutput,
	open func(context.Context, *configuration.Model, core.EnvelopeRekeyInstallation) (configurationRekeyEngine, error)) core.PublicApplyResult {
	m, i, out, ok := configurationAccessMutationSource(ctx, requestID, pair)
	if !ok {
		return out
	}
	if len(name) > contract.CryptoMaxName || !utf8.ValidString(name) {
		return configurationApplyFailure(ctx, out, "declaration", nil)
	}
	if err := configureMaintenanceOutput(ctx, pair, m, &i, output, configuration.MaintenanceRequest{OperationKind: contract.OperationEnvelopeRekey, Name: name}); err != nil {
		return configurationApplyFailure(ctx, out, "output", err)
	}
	if open == nil {
		return configurationApplyFailure(ctx, out, "context", nil)
	}
	engine, err := open(ctx, m, core.EnvelopeRekeyInstallation{AccessMutationInstallation: i, Name: name})
	if err != nil || engine == nil {
		return configurationAccessMutationUnavailable(ctx, out)
	}
	releaseConfigurationBasis(m)
	i = core.AccessMutationInstallation{}
	defer engine.Close()
	return finishConfigurationAccessMutation(ctx, engine.Rekey(ctx, requestID), out, "rekey")
}

func configurationAccessMutationSource(ctx context.Context, requestID contract.ID, pair *configuration.Pair) (*configuration.Model, core.AccessMutationInstallation, core.PublicApplyResult, bool) {
	var format configuration.Format
	if pair != nil {
		format = pair.Format
	}
	out, err := newConfigurationApplyResult(requestID, format)
	if err != nil {
		return nil, core.AccessMutationInstallation{}, out, false
	}
	fail := func(stage string, err error) (*configuration.Model, core.AccessMutationInstallation, core.PublicApplyResult, bool) {
		return nil, core.AccessMutationInstallation{}, configurationApplyFailure(ctx, out, stage, err), false
	}
	m, err := configuration.Parse(ctx, pair)
	if err != nil {
		return fail("parse", err)
	}
	if !m.Resolved {
		return fail("declaration", &configuration.Diagnostic{Field: "generated", Reason: "restore-exact-generated-file"})
	}
	basis, store, err := configurationPublicBasis(m)
	if err != nil {
		return fail("declaration", err)
	}
	control, err := basis.ControlCore(m.DomainID, store)
	if err != nil {
		return fail("declaration", err)
	}
	if ctx == nil || ctx.Err() != nil || requestID.IsZero() {
		return fail("context", nil)
	}
	if deadline, finite := ctx.Deadline(); !finite || !time.Now().Before(deadline) {
		return fail("context", &configuration.Diagnostic{Reason: "expired"})
	}
	i := core.AccessMutationInstallation{ExpectedDomain: m.DomainID, ExpectedStore: store, PublicBasis: basis, ExpectedControl: control, CompositionID: CompatibilityManifest().Identity}
	return m, i, out, true
}

func configurationRecipientReference(m *configuration.Model, reference string) (contract.RecipientBindingReference, error) {
	if m == nil || reference == "" || len(reference) > 256 || !utf8.ValidString(reference) {
		return contract.RecipientBindingReference{}, contract.ErrRecord
	}
	for _, row := range m.Recipients {
		if row.Reference != reference {
			continue
		}
		binding, err := configurationApplyBinding(m.Provider, row.Encryption)
		if err != nil {
			return contract.RecipientBindingReference{}, err
		}
		digest, err := contract.PublicBindingDigest(binding)
		if err != nil || row.ID.IsZero() {
			return contract.RecipientBindingReference{}, contract.ErrRecord
		}
		return contract.RecipientBindingReference{RecipientID: row.ID, PublicBindingDigest: digest}, nil
	}
	return contract.RecipientBindingReference{}, contract.ErrRecord
}

func configurationAccessMutationUnavailable(ctx context.Context, out core.PublicApplyResult) core.PublicApplyResult {
	out = configurationApplyFailure(ctx, out, "construction", nil)
	out.Result = core.Result{Outcome: core.EvidenceUnavailable, Reason: core.CustodyUnavailable}
	out.Diagnostics[0].Reason = contract.ReasonEvidenceUnavailable
	out.PreAdmission.Code = string(contract.ReasonEvidenceUnavailable)
	return out
}

func finishConfigurationAccessMutation(ctx context.Context, result, correlation core.PublicApplyResult, stage string) core.PublicApplyResult {
	if !result.RequestIdentity.IsZero() {
		return result
	}
	if result.OperationID.IsZero() {
		result.OperationID = correlation.OperationID
	}
	correlation.PreAdmission.Stage = stage
	correlation.PreAdmission.Code = string(configurationMutationObservationReason(ctx, result.Result))
	result.PreAdmission = correlation.PreAdmission
	return result
}

// RekeyConfigurationEnvelopeFile captures the named output before the source.
func RekeyConfigurationEnvelopeFile(ctx context.Context, requestID contract.ID, path string, format configuration.Format, name, outputPath string) MaintenanceCommandResult {
	return runConfigurationMaintenance(ctx, requestID, path, format, configuration.MaintenanceRequest{OperationKind: contract.OperationEnvelopeRekey, Name: name}, outputPath, defaultReplacementObservationSource)
}

func openConfigurationAccessMutation(ctx context.Context, m *configuration.Model, i core.AccessMutationInstallation) (core.AccessMutationInstallation, *enkvcrypto.Runtime, contract.ID, error) {
	config, route, err := configurationApplyConfig(m, i.ExpectedControl)
	if err != nil {
		return i, nil, route, err
	}
	config, err = LoadDefaultConfig(ctx, config)
	if err != nil {
		return i, nil, route, err
	}
	cell, err := New(ctx, config)
	if err != nil {
		return i, nil, route, err
	}
	runtime, ok := cell.Crypto.(*enkvcrypto.Runtime)
	if !ok {
		return i, nil, route, ErrCell
	}
	i.Store, i.Trust, i.CloseInstalled = cell.Store, cell.Trust, runtime.Close
	if i.ConfigurationValidator == nil {
		i.ConfigurationValidator = core.NewPublicConfigurationValidator(nil)
	}
	return i, runtime, route, nil
}

func openConfigurationEnvelopeRekey(ctx context.Context, m *configuration.Model, i core.EnvelopeRekeyInstallation) (configurationRekeyEngine, error) {
	installation, runtime, route, err := openConfigurationAccessMutation(ctx, m, i.AccessMutationInstallation)
	if err != nil {
		return nil, err
	}
	i.AdmitCustody = func(ctx context.Context, q contract.CryptoCompareRequest, control contract.ControlCore, current []contract.RecipientRecord, plain []contract.MembershipRow, support contract.DescriptorVector, witness *contract.GeneratedSupportTransition, revision contract.ID, before contract.MutationReceiptWindows, warningBits uint8, deadline time.Time) (*core.InstalledApplyCustody, error) {
		owner, err := enkvcrypto.NewEnvelopeRekeyCustody(runtime, q, control, current, route, plain, support, witness, revision, before, warningBits, deadline)
		if err != nil {
			return nil, err
		}
		return &core.InstalledApplyCustody{Crypto: owner, BindReceipt: owner.BindReceipt, Close: owner.Close}, nil
	}
	i.AccessMutationInstallation = installation
	engine, err := core.NewInstalledEnvelopeRekey(i)
	if err != nil {
		runtime.Close()
		return nil, err
	}
	return engine, err
}

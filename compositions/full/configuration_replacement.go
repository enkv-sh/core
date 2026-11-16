package compositionfull

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

var errConfigurationReplacement = errors.New("key replacement configuration refused")

type configurationReplacementOperation struct {
	providers configurationReplacementProviders
	family    contract.Family
	control   contract.ControlCore
	target    core.ReplacementTarget
	recipient contract.ID
	goal      core.RoleReplacementGoal
}

// The caller prepares the exact named output and dispatches existing-output
// observation before entering this fresh mutation adapter. Pair and output are
// borrowed until return; their caller retains and reports Close errors.
func replaceConfigurationKeys(ctx context.Context, requestID contract.ID, pair *configuration.Pair,
	request configuration.ReplacementRequest, output *configuration.SuccessorOutput) (core.PublicReplacementResult, error) {
	return replaceConfigurationKeysWithProviders(ctx, requestID, pair, request, output, openConfigurationReplacementProviders)
}

func replaceConfigurationKeysWithProviders(ctx context.Context, requestID contract.ID, pair *configuration.Pair,
	request configuration.ReplacementRequest, output *configuration.SuccessorOutput,
	open func(context.Context, *configuration.Model) (configurationReplacementProviders, error)) (core.PublicReplacementResult, error) {
	if ctx == nil || ctx.Err() != nil || requestID.IsZero() || pair == nil || output == nil || output.Existing() != nil || open == nil {
		return core.PublicReplacementResult{}, errConfigurationReplacement
	}
	deadline, finite := ctx.Deadline()
	if !finite || !time.Now().Before(deadline) {
		return core.PublicReplacementResult{}, errConfigurationReplacement
	}
	if err := output.CheckUnchanged(ctx); err != nil {
		return core.PublicReplacementResult{}, err
	}
	model, err := configuration.Parse(ctx, pair)
	if err != nil {
		return core.PublicReplacementResult{}, err
	}
	common, operation, row, err := configurationReplacementInput(model, request)
	if err != nil {
		return core.PublicReplacementResult{}, err
	}
	providers, err := open(ctx, model)
	if err != nil {
		return core.PublicReplacementResult{}, err
	}
	var closeOnce sync.Once
	closeProviders := func() {
		closeOnce.Do(func() {
			if providers.close != nil {
				providers.close()
			}
		})
	}
	defer closeProviders()
	operation.providers = providers
	common.Store = providers.store
	common.SourceUnchanged = output.CheckUnchanged
	common.ResolvePublicGoal = operation.resolvePublicGoal
	common.ConstructSigners = operation.constructSigners
	common.CloseInstalled = closeProviders
	common.PublishSuccessor = func(ctx context.Context, successor core.ReplacementSuccessor) (core.ReplacementReadback, error) {
		material := configuration.SuccessorMaterial{Control: successor.Control, Basis: configurationReplacementBasis(successor.Basis),
			RequestIdentity: successor.RequestIdentity, SignedCandidate: successor.Correlation.SignedCandidate}
		for _, fact := range successor.Recipients {
			material.Recipients = append(material.Recipients, configuration.ReplacementRecipientFact{RecipientID: fact.RecipientID, Encryption: fact.Encryption})
		}
		readback, err := output.Publish(ctx, material)
		if err != nil {
			return core.ReplacementReadback{}, err
		}
		return configurationReplacementReadback(ctx, readback)
	}
	switch operation.target {
	case core.ReplacementTargetAuthority:
		if operation.goal.EncryptionSelector != "" {
			common.AdmitSuccessionCustody = operation.admitSuccessionCustody
		}
		engine, err := core.NewInstalledAuthorityReplacement(core.AuthorityReplacementInstallation{ReplacementInstallation: common, Goal: operation.goal})
		if err != nil {
			return core.PublicReplacementResult{}, err
		}
		releaseConfigurationBasis(model)
		common = core.ReplacementInstallation{}
		defer engine.Close()
		return engine.Replace(ctx, requestID), nil
	case core.ReplacementTargetRecovery:
		if operation.goal.EncryptionSelector != "" {
			common.AdmitSuccessionCustody = operation.admitSuccessionCustody
		}
		engine, err := core.NewInstalledRecoveryReplacement(core.RecoveryReplacementInstallation{ReplacementInstallation: common, Goal: operation.goal})
		if err != nil {
			return core.PublicReplacementResult{}, err
		}
		releaseConfigurationBasis(model)
		common = core.ReplacementInstallation{}
		defer engine.Close()
		return engine.Replace(ctx, requestID), nil
	case core.ReplacementTargetRecipient:
		common.AdmitRecipientCustody = operation.admitRecipientCustody
		engine, err := core.NewInstalledRecipientReplacement(core.RecipientReplacementInstallation{ReplacementInstallation: common,
			RecipientID: operation.recipient, RecipientRow: row, EncryptionSelector: operation.goal.EncryptionSelector})
		if err != nil {
			return core.PublicReplacementResult{}, err
		}
		releaseConfigurationBasis(model)
		common = core.ReplacementInstallation{}
		defer engine.Close()
		return engine.Replace(ctx, requestID), nil
	}
	return core.PublicReplacementResult{}, errConfigurationReplacement
}

func configurationReplacementInput(model *configuration.Model, request configuration.ReplacementRequest) (core.ReplacementInstallation, configurationReplacementOperation, uint16, error) {
	refuse := func() (core.ReplacementInstallation, configurationReplacementOperation, uint16, error) {
		return core.ReplacementInstallation{}, configurationReplacementOperation{}, 0, errConfigurationReplacement
	}
	if model == nil || !model.Resolved || (request.Authorizer != contract.NormalSigningRole && request.Authorizer != contract.RecoverySigningRole) {
		return refuse()
	}
	basis, store, err := configurationPublicBasis(model)
	if err != nil {
		return refuse()
	}
	control, err := basis.ControlCore(model.DomainID, store)
	if err != nil || !configurationReplacementRoleFacts(model, control) {
		return refuse()
	}
	captured, err := configurationReplacementRecipientFacts(model)
	if err != nil {
		return refuse()
	}
	operation := configurationReplacementOperation{family: model.Provider, control: control,
		goal: core.RoleReplacementGoal{ApprovalRole: request.Authorizer, SigningSelector: request.SigningSelector, EncryptionSelector: request.EncryptionSelector}}
	var recipientRow uint16
	switch request.Target {
	case configuration.ReplaceAuthority, configuration.ReplaceRecovery:
		if request.RecipientReference != "" || (request.SigningSelector == "" && request.EncryptionSelector == "") {
			return refuse()
		}
		operation.target = core.ReplacementTargetAuthority
		if request.Target == configuration.ReplaceRecovery {
			operation.target = core.ReplacementTargetRecovery
		}
		if request.EncryptionSelector == "" {
			if request.MaterialSource != "" {
				return refuse()
			}
		} else {
			switch request.MaterialSource {
			case "authority":
				operation.goal.MaterialSource = core.ReplacementMaterialAuthority
			case "recovery":
				operation.goal.MaterialSource = core.ReplacementMaterialRecovery
			default:
				return refuse()
			}
		}
	case configuration.ReplaceRecipient:
		if request.RecipientReference == "" || request.SigningSelector != "" || request.EncryptionSelector == "" ||
			request.Authorizer != contract.NormalSigningRole || request.MaterialSource != "authority" {
			return refuse()
		}
		operation.target = core.ReplacementTargetRecipient
		for _, recipient := range model.Recipients {
			if recipient.Reference == request.RecipientReference {
				operation.recipient = recipient.ID
				break
			}
		}
		found := false
		for index, recipient := range model.GeneratedRecipients {
			if recipient.Reference == request.RecipientReference && recipient.ID == operation.recipient {
				recipientRow, found = uint16(index), true
				break
			}
		}
		if !found || operation.recipient.IsZero() {
			return refuse()
		}
	default:
		return refuse()
	}
	return core.ReplacementInstallation{ExpectedDomain: model.DomainID, ExpectedStore: store, PublicBasis: basis, ExpectedControl: control,
		CapturedRecipients: captured, FileIdentity: model.FileID, CompositionID: CompatibilityManifest().Identity}, operation, recipientRow, nil
}

func configurationReplacementRecipientFacts(model *configuration.Model) ([]core.ReplacementRecipientFact, error) {
	facts := make([]core.ReplacementRecipientFact, 0, len(model.GeneratedRecipients))
	for _, recipient := range model.GeneratedRecipients {
		binding, err := configurationApplyBinding(model.Provider, recipient.Encryption)
		if err != nil {
			return nil, err
		}
		facts = append(facts, core.ReplacementRecipientFact{RecipientID: recipient.ID, Encryption: binding})
	}
	return facts, nil
}

func (operation *configurationReplacementOperation) resolvePublicGoal(ctx context.Context, request core.ReplacementPublicRequest) (core.ReplacementPublicGoal, error) {
	role := uint8(0)
	if operation.goal.SigningSelector != "" {
		role = contract.NormalSigningRole
		if operation.target == core.ReplacementTargetRecovery {
			role = contract.RecoverySigningRole
		}
	}
	if request.Provider != operation.family || request.SigningRole != role || request.SigningSelector != operation.goal.SigningSelector || request.EncryptionSelector != operation.goal.EncryptionSelector {
		return core.ReplacementPublicGoal{}, errConfigurationReplacement
	}
	goal := core.ReplacementPublicGoal{Provider: operation.family}
	var err error
	if request.SigningSelector != "" {
		goal.Signing, err = operation.providers.signing(ctx, request.SigningSelector, role)
		if err != nil {
			return core.ReplacementPublicGoal{}, err
		}
	}
	if request.EncryptionSelector != "" {
		goal.Encryption, err = operation.providers.encryption(ctx, request.EncryptionSelector)
		if err != nil {
			return core.ReplacementPublicGoal{}, err
		}
	}
	return goal, nil
}

func (operation *configurationReplacementOperation) constructSigners(ctx context.Context, authorizer contract.PublicSigningBinding, successor *contract.PublicSigningBinding) (core.SuccessionSigners, func(), error) {
	expected := operation.control.NormalSigning
	if operation.goal.ApprovalRole == contract.RecoverySigningRole {
		if operation.control.Recovery == nil {
			return core.SuccessionSigners{}, nil, errConfigurationReplacement
		}
		expected = operation.control.Recovery.Signing
	}
	x, err := contract.EncodePublicSigningBinding(expected)
	if err != nil {
		return core.SuccessionSigners{}, nil, err
	}
	y, err := contract.EncodePublicSigningBinding(authorizer)
	if err != nil || !bytes.Equal(x, y) {
		return core.SuccessionSigners{}, nil, errConfigurationReplacement
	}
	role := uint8(contract.NormalSigningRole)
	if operation.target == core.ReplacementTargetRecovery {
		role = contract.RecoverySigningRole
	}
	if successor != nil && (operation.target == core.ReplacementTargetRecipient || operation.goal.SigningSelector == "" || successor.Provider != operation.family ||
		successor.Role != role || successor.KeySelector != operation.goal.SigningSelector) {
		return core.SuccessionSigners{}, nil, errConfigurationReplacement
	}
	current, err := operation.providers.signer(ctx, authorizer)
	if err != nil {
		return core.SuccessionSigners{}, nil, err
	}
	signers := core.SuccessionSigners{Authorizer: current}
	if successor != nil {
		trust, err := operation.providers.signer(ctx, *successor)
		if err != nil {
			return core.SuccessionSigners{}, nil, err
		}
		if role == contract.NormalSigningRole {
			signers.NormalSuccessor = trust
		} else {
			signers.RecoverySuccessor = trust
		}
	}
	return signers, func() {}, nil
}

func configurationReplacementBasis(source core.PublicBasis) configuration.Basis {
	basis := configuration.Basis{Descriptor: source.Descriptor, Control: source.Control, Selection: source.Selection,
		SigningAnchor: source.SigningAnchor, StoreConfiguration: source.StoreConfiguration, HEAD: source.HEAD, Root: source.Root, RecipientPages: source.RecipientPages}
	for _, row := range source.Enrollment {
		basis.Enrollment = append(basis.Enrollment, configuration.Enrollment{ID: row.RecipientID, Status: row.Status, DisplayName: row.DisplayName})
	}
	return basis
}

func configurationReplacementReadback(ctx context.Context, readback *configuration.SuccessorReadback) (core.ReplacementReadback, error) {
	if readback == nil || readback.Pair == nil || readback.Model == nil || readback.Model.Replacement == nil {
		return core.ReplacementReadback{}, errConfigurationReplacement
	}
	if err := readback.Pair.CheckUnchanged(ctx); err != nil {
		return core.ReplacementReadback{}, err
	}
	model := readback.Model
	basis, store, err := configurationPublicBasis(model)
	if err != nil {
		return core.ReplacementReadback{}, err
	}
	control, err := basis.ControlCore(model.DomainID, store)
	if err != nil {
		return core.ReplacementReadback{}, err
	}
	if !configurationReplacementRoleFacts(model, control) {
		return core.ReplacementReadback{}, errConfigurationReplacement
	}
	recipients, err := configurationReplacementRecipientFacts(model)
	if err != nil {
		return core.ReplacementReadback{}, err
	}
	target, known := replacementCommandTarget(model.Replacement.Request.Target)
	if !known {
		return core.ReplacementReadback{}, errConfigurationReplacement
	}
	return core.ReplacementReadback{Basis: basis, FileIdentity: model.FileID, Control: control, Recipients: recipients,
		Correlation: core.ReplacementCorrelation{Target: target, RecipientID: model.Replacement.RecipientID,
			RequestIdentity: model.Replacement.RequestIdentity, SignedCandidate: model.Replacement.SignedCandidate}}, nil
}

func configurationReplacementRoleFacts(model *configuration.Model, control contract.ControlCore) bool {
	if model.Authority.ID != control.AuthorityRecipientID || model.Authority.Signing.Selector != control.NormalSigning.KeySelector ||
		!bytes.Equal(model.Authority.Signing.PublicKey, control.NormalSigning.SPKI) || model.RecoveryEnabled != (control.Recovery != nil) {
		return false
	}
	authority, err := configurationApplyBinding(model.Provider, model.Authority.Encryption)
	if err != nil || !sameConfigurationReplacementBindingRow(contract.BindingTableRow{Binding: authority}, contract.BindingTableRow{Binding: control.AuthorityKMSBinding}) {
		return false
	}
	if control.Recovery != nil {
		if model.Recovery.Signing.Selector != control.Recovery.Signing.KeySelector || !bytes.Equal(model.Recovery.Signing.PublicKey, control.Recovery.Signing.SPKI) {
			return false
		}
		recovery, err := configurationApplyBinding(model.Provider, model.Recovery.Encryption)
		if err != nil || !sameConfigurationReplacementBindingRow(contract.BindingTableRow{Binding: recovery}, contract.BindingTableRow{Binding: control.Recovery.KMS}) {
			return false
		}
	}
	return true
}

package compositionfull

import (
	"bytes"
	"context"
	"sync"
	"time"

	"enkv.sh/core"
	"enkv.sh/core/contract"
	enkvcrypto "enkv.sh/crypto"
)

func (operation *configurationReplacementOperation) admitSuccessionCustody(ctx context.Context, request contract.CryptoAccessReplaceRequest,
	succession contract.SuccessionRequestCore, before contract.ControlCore, source contract.BindingTableRow, probe contract.SuccessorKEKProbeCore,
	rows []contract.CompactRow, deadline time.Time) (*core.InstalledReplacementCustody, error) {
	kind := uint8(contract.SuccessionReplaceAuthority)
	if operation.target == core.ReplacementTargetRecovery {
		kind = contract.SuccessionReplaceRecoveryBasis
	}
	if operation.target == core.ReplacementTargetRecipient || operation.goal.EncryptionSelector == "" || succession.OperationKind != kind ||
		succession.ApprovalRole != operation.goal.ApprovalRole || before.Provider != operation.family || len(request.Replacements) != 1 {
		return nil, errConfigurationReplacement
	}
	materialRole := uint8(contract.SuccessionMaterialAuthority)
	if operation.goal.MaterialSource == core.ReplacementMaterialRecovery {
		materialRole = contract.SuccessionMaterialRecovery
	}
	if succession.MaterialSourceRole != materialRole {
		return nil, errConfigurationReplacement
	}
	selected, err := operation.materialBinding(operation.control)
	if err != nil || !sameConfigurationReplacementBindingRow(selected, source) {
		return nil, errConfigurationReplacement
	}
	index := int(request.Replacements[0].SuccessorBindingIndex)
	if index >= len(request.BindingTable) {
		return nil, errConfigurationReplacement
	}
	successor := request.BindingTable[index]
	if successor.SubjectKind != configurationReplacementTargetKind(operation.target) || successor.SubjectID != configurationReplacementTargetID(operation.target, before) ||
		successor.Binding.KeySelector != operation.goal.EncryptionSelector {
		return nil, errConfigurationReplacement
	}
	sourceRoute := configurationReplacementRoute("source", request.Context.AdmissionID, source.Binding.BindingID)
	successorRoute := configurationReplacementRoute("successor", request.Context.AdmissionID, successor.Binding.BindingID)
	sourceKey, err := operation.providers.privateKey(ctx, source.Binding, sourceRoute)
	if err != nil {
		return nil, err
	}
	successorKey, err := operation.providers.privateKey(ctx, successor.Binding, successorRoute)
	if err != nil {
		return nil, err
	}
	runtime, err := enkvcrypto.New(operation.family, []enkvcrypto.KeyAccess{sourceKey, successorKey})
	if err != nil {
		return nil, err
	}
	custody, err := enkvcrypto.NewSuccessionReplacementCustody(runtime, request, succession, before, source, probe, rows,
		sourceRoute, successorRoute, successorRoute, deadline)
	if err != nil {
		runtime.Close()
		return nil, err
	}
	return ownConfigurationReplacementCustody(runtime, custody), nil
}

func (operation *configurationReplacementOperation) admitRecipientCustody(ctx context.Context, request contract.CryptoAccessReplaceRequest,
	intent contract.RecipientReplacementIntent, transition contract.RequestCore, before contract.ControlCore,
	rows []contract.CompactRow, deadline time.Time) (*core.InstalledReplacementCustody, error) {
	if operation.target != core.ReplacementTargetRecipient || intent.RecipientID != operation.recipient ||
		intent.Successor.KeySelector != operation.goal.EncryptionSelector || before.Provider != operation.family ||
		before.AuthorityRecipientID != operation.control.AuthorityRecipientID ||
		!sameConfigurationReplacementBindingRow(contract.BindingTableRow{Binding: before.AuthorityKMSBinding}, contract.BindingTableRow{Binding: operation.control.AuthorityKMSBinding}) {
		return nil, errConfigurationReplacement
	}
	sourceRoute := configurationReplacementRoute("source", request.Context.AdmissionID, before.AuthorityKMSBinding.BindingID)
	publicRoute := configurationReplacementRoute("successor-public", request.Context.AdmissionID, intent.Successor.BindingID)
	sourceKey, err := operation.providers.privateKey(ctx, before.AuthorityKMSBinding, sourceRoute)
	if err != nil {
		return nil, err
	}
	successorPublic, err := operation.providers.publicKey(ctx, intent.Successor, publicRoute)
	if err != nil {
		return nil, err
	}
	runtime, err := enkvcrypto.New(operation.family, []enkvcrypto.KeyAccess{sourceKey})
	if err != nil {
		return nil, err
	}
	custody, err := enkvcrypto.NewRecipientReplacementCustody(runtime, request, intent, transition, before, rows, sourceRoute, successorPublic, deadline)
	if err != nil {
		runtime.Close()
		return nil, err
	}
	return ownConfigurationReplacementCustody(runtime, custody), nil
}

func ownConfigurationReplacementCustody(runtime *enkvcrypto.Runtime, custody *enkvcrypto.ReplacementCustody) *core.InstalledReplacementCustody {
	var closeOnce sync.Once
	return &core.InstalledReplacementCustody{Crypto: custody, Close: func() {
		closeOnce.Do(func() {
			custody.Close()
			runtime.Close()
		})
	}}
}

func (operation *configurationReplacementOperation) materialBinding(control contract.ControlCore) (contract.BindingTableRow, error) {
	switch operation.goal.MaterialSource {
	case core.ReplacementMaterialAuthority:
		return contract.BindingTableRow{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: control.AuthorityRecipientID, Binding: control.AuthorityKMSBinding}, nil
	case core.ReplacementMaterialRecovery:
		if control.Recovery != nil {
			return contract.BindingTableRow{SubjectKind: contract.RecoveryWrapSubject, SubjectID: control.Recovery.RoleID, Binding: control.Recovery.KMS}, nil
		}
	}
	return contract.BindingTableRow{}, errConfigurationReplacement
}

func sameConfigurationReplacementBindingRow(a, b contract.BindingTableRow) bool {
	if a.SubjectKind != b.SubjectKind || a.SubjectID != b.SubjectID {
		return false
	}
	x, err := contract.EncodeKMSBinding(a.Binding)
	if err != nil {
		return false
	}
	y, err := contract.EncodeKMSBinding(b.Binding)
	return err == nil && bytes.Equal(x, y)
}

func configurationReplacementTargetKind(target core.ReplacementTarget) uint8 {
	if target == core.ReplacementTargetRecovery {
		return contract.RecoveryWrapSubject
	}
	return contract.OrdinaryWrapSubject
}

func configurationReplacementTargetID(target core.ReplacementTarget, before contract.ControlCore) contract.ID {
	if target == core.ReplacementTargetRecovery && before.Recovery != nil {
		return before.Recovery.RoleID
	}
	return before.AuthorityRecipientID
}

func configurationReplacementRoute(purpose string, admission, binding contract.ID) contract.ID {
	body := append([]byte("enkv/keys-replacement/"+purpose+"-route/v1\x00"), admission[:]...)
	return contract.Hash(append(body, binding[:]...))
}

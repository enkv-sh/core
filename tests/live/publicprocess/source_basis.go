package main

import (
	"bytes"
	"errors"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

var errPublicSourceBasis = errors.New("public source basis refused")

func publicSourceBasis(model *configuration.Model) (core.PublicBasis, contract.Descriptor, contract.ControlCore, error) {
	basis := core.PublicBasis{Descriptor: model.Basis.Descriptor, Control: model.Basis.Control, Selection: model.Basis.Selection, Enrollment: make([]core.PublicEnrollment, len(model.Basis.Enrollment)),
		SigningAnchor: model.Basis.SigningAnchor, StoreConfiguration: model.Basis.StoreConfiguration, HEAD: model.Basis.HEAD, Root: model.Basis.Root, RecipientPages: model.Basis.RecipientPages}
	for i, row := range model.Basis.Enrollment {
		basis.Enrollment[i] = core.PublicEnrollment{RecipientID: row.ID, Status: row.Status, DisplayName: row.DisplayName}
	}
	descriptor := contract.Descriptor{Family: model.Provider, Prefix: model.Store.PrefixBeforeHEAD, HeadKey: model.Store.PrefixBeforeHEAD + "/HEAD"}
	if len(basis.Descriptor) != 0 {
		genesis, err := contract.DecodeGenesisDescriptorCore(basis.Descriptor)
		if err != nil {
			return basis, descriptor, contract.ControlCore{}, errors.Join(errPublicSourceBasis, err)
		}
		descriptor.Identity, descriptor.Coordinate, descriptor.NonBody = genesis.StoreID, genesis.CoordinateID, genesis.NonBodyID
	} else if len(basis.HEAD) != 0 {
		head, err := format.DecodeHead(basis.HEAD)
		if err != nil {
			return basis, descriptor, contract.ControlCore{}, errors.Join(errPublicSourceBasis, err)
		}
		descriptor.Identity, descriptor.Coordinate, descriptor.NonBody = head.Core.Store, head.Core.Coordinate, head.Core.NonBody
	} else {
		control, err := contract.DecodeControlCore(basis.Control)
		if err != nil {
			return basis, descriptor, contract.ControlCore{}, errors.Join(errPublicSourceBasis, err)
		}
		descriptor.Identity, descriptor.Coordinate, descriptor.NonBody = control.StoreID, control.CoordinateID, control.NonBodyID
	}
	storeID, err := contract.StoreConfigurationID(contract.StoreConfiguration{Provider: model.Provider, ConstructionProfile: contract.StoreConstructionProfile,
		DomainID: model.DomainID, Region: model.Store.Region, Bucket: model.Store.Bucket, PrefixBeforeHEAD: model.Store.PrefixBeforeHEAD, ExpectedOwner: model.Store.ExpectedOwner})
	if err != nil || storeID != descriptor.Identity {
		return basis, descriptor, contract.ControlCore{}, errors.Join(errPublicSourceBasis, err)
	}
	control, err := basis.ControlCore(model.DomainID, descriptor)
	if err != nil || control.AuthorityRecipientID != model.Authority.ID ||
		control.NormalSigning.KeySelector != model.Authority.SigningSelector || !bytes.Equal(control.NormalSigning.SPKI, model.Authority.Signing.PublicKey) ||
		!publicEncryptionMatches(model.Authority.Encryption, control.AuthorityKMSBinding) ||
		(control.Recovery != nil) != model.RecoveryEnabled ||
		model.RecoveryEnabled && (control.Recovery.Signing.KeySelector != model.Recovery.SigningSelector ||
			!bytes.Equal(control.Recovery.Signing.SPKI, model.Recovery.Signing.PublicKey) ||
			!publicEncryptionMatches(model.Recovery.Encryption, control.Recovery.KMS)) {
		return basis, descriptor, control, errors.Join(errPublicSourceBasis, err)
	}
	return basis, descriptor, control, nil
}

func publicEncryptionMatches(key configuration.Key, binding contract.KMSBinding) bool {
	return key.Selector == binding.KeySelector && bytes.Equal(key.PublicKey, binding.SPKI) &&
		key.Binding.ID == binding.BindingID && key.Binding.Incarnation == binding.BindingIncarnationID &&
		key.Binding.Serial == binding.BindingSerial && key.Binding.Protection == binding.ProtectionClass
}

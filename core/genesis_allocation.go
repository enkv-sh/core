package core

import (
	"crypto/rand"
	"io"
	"slices"
	"sync"

	"enkv.sh/core/contract"
)

type InitializationEncryptionIDs struct{ BindingID, BindingIncarnationID contract.ID }
type InitializationRecipientIDs struct {
	RecipientID contract.ID
	Encryption  InitializationEncryptionIDs
}
type InitializationSigningIDs struct{ BindingID, ControlIncarnationID contract.ID }
type InitializationRecoveryIDs struct {
	RoleID     contract.ID
	Signing    InitializationSigningIDs
	Encryption InitializationEncryptionIDs
}

// InitializationIDs are public allocations. They grant no Store, key-use or
// initialization admission. Additional recipients retain source order here;
// the canonical descriptor sorts their resulting records by RecipientID.
type InitializationIDs struct {
	InitID, DomainID, DescriptorArtifactID, ManifestArtifactID contract.ID
	NormalSigning                                              InitializationSigningIDs
	Authority                                                  InitializationRecipientIDs
	Recipients                                                 []InitializationRecipientIDs
	Recovery                                                   *InitializationRecoveryIDs
}

type InitializationAllocation struct {
	mu        sync.Mutex
	ids       InitializationIDs
	installed bool
}

func AllocateInitialization(additionalRecipientCount uint16, recoveryEnabled bool) (*InitializationAllocation, error) {
	return allocateInitialization(rand.Reader, additionalRecipientCount, recoveryEnabled)
}

func allocateInitialization(entropy io.Reader, additional uint16, recovery bool) (*InitializationAllocation, error) {
	if int(additional) >= contract.CryptoMaxRecipients || entropy == nil {
		return nil, contract.ErrRecordCapacity
	}
	base, err := allocateGenesisIDs(entropy)
	if err != nil {
		return nil, err
	}
	ids := InitializationIDs{InitID: base.Init, DomainID: base.Domain, DescriptorArtifactID: base.DescriptorArtifact,
		ManifestArtifactID: base.ManifestArtifact, Recipients: make([]InitializationRecipientIDs, additional)}
	used := map[contract.ID]bool{base.Init: true, base.Domain: true, base.DescriptorArtifact: true, base.ManifestArtifact: true}
	fill := func(target *contract.ID) error {
		if _, err := io.ReadFull(entropy, target[:]); err != nil {
			return err
		}
		if target.IsZero() || used[*target] {
			return contract.ErrRecord
		}
		used[*target] = true
		return nil
	}
	var fields []*contract.ID
	fields = append(fields, &ids.NormalSigning.BindingID, &ids.NormalSigning.ControlIncarnationID,
		&ids.Authority.RecipientID, &ids.Authority.Encryption.BindingID, &ids.Authority.Encryption.BindingIncarnationID)
	for i := range ids.Recipients {
		r := &ids.Recipients[i]
		fields = append(fields, &r.RecipientID, &r.Encryption.BindingID, &r.Encryption.BindingIncarnationID)
	}
	if recovery {
		ids.Recovery = &InitializationRecoveryIDs{}
		r := ids.Recovery
		fields = append(fields, &r.RoleID, &r.Signing.BindingID, &r.Signing.ControlIncarnationID,
			&r.Encryption.BindingID, &r.Encryption.BindingIncarnationID)
	}
	for _, field := range fields {
		if err := fill(field); err != nil {
			return nil, err
		}
	}
	return &InitializationAllocation{ids: ids}, nil
}

func (a *InitializationAllocation) Identities() InitializationIDs {
	if a == nil {
		return InitializationIDs{}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	out := a.ids
	out.Recipients = slices.Clone(out.Recipients)
	if out.Recovery != nil {
		recovery := *out.Recovery
		out.Recovery = &recovery
	}
	return out
}

func initializationIDsMatch(ids InitializationIDs, d contract.GenesisDescriptorCore) bool {
	if ids.InitID != d.InitID || ids.DomainID != d.DomainID || ids.DescriptorArtifactID != d.DescriptorArtifactID ||
		ids.ManifestArtifactID != d.ManifestArtifactID || ids.NormalSigning.BindingID != d.NormalSigning.BindingID ||
		ids.NormalSigning.ControlIncarnationID != d.NormalSigning.Binding.ControlIncarnationID ||
		ids.Authority.RecipientID != d.AuthorityRecipientID || len(d.Recipients) != len(ids.Recipients)+1 ||
		(ids.Recovery == nil) != (d.Recovery == nil) {
		return false
	}
	matches := func(expected InitializationRecipientIDs) bool {
		for _, row := range d.Recipients {
			if row.RecipientID == expected.RecipientID {
				return row.CurrentBinding != nil && row.CurrentBinding.BindingID == expected.Encryption.BindingID &&
					row.CurrentBinding.BindingIncarnationID == expected.Encryption.BindingIncarnationID
			}
		}
		return false
	}
	if !matches(ids.Authority) {
		return false
	}
	for _, row := range ids.Recipients {
		if !matches(row) {
			return false
		}
	}
	if ids.Recovery != nil {
		r, actual := ids.Recovery, d.Recovery
		return r.RoleID == actual.RoleID && r.Signing.BindingID == actual.Signing.BindingID &&
			r.Signing.ControlIncarnationID == actual.Signing.Binding.ControlIncarnationID &&
			r.Encryption.BindingID == actual.KMS.BindingID && r.Encryption.BindingIncarnationID == actual.KMS.BindingIncarnationID
	}
	return true
}

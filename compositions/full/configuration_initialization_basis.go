package compositionfull

import (
	"bytes"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core/contract"
)

// The current pair can name an old initialization only through the exact
// descriptor facts. Draft output settings and source formatting are not the
// original capture: the authenticated request retains its own SetupDigest.
func validInitializationObservationBasis(m *configuration.Model, d contract.GenesisDescriptorCore, manifest []byte) bool {
	if m == nil || !m.Resolved || len(m.Entries) != 0 || m.Provider != d.Provider || m.DomainID != d.DomainID ||
		m.Authority.ID != d.AuthorityRecipientID || m.RecoveryEnabled != (d.Recovery != nil) || len(m.Recipients)+1 != len(d.Recipients) {
		return false
	}
	descriptor, err := contract.EncodeGenesisDescriptorCore(d)
	if err != nil || !bytes.Equal(descriptor, m.Basis.Descriptor) || len(m.Basis.Control) != 0 || len(m.Basis.Selection) != 0 || len(m.Basis.Enrollment) != 0 ||
		len(m.Basis.SigningAnchor) != 0 || len(m.Basis.StoreConfiguration) != 0 || len(m.Basis.HEAD) != 0 || len(m.Basis.Root) != 0 || len(m.Basis.RecipientPages) != 0 {
		return false
	}
	stored, err := contract.DecodeGenesisBootstrapManifestCore(manifest)
	if err != nil || stored.DescriptorDigest != contract.Hash(descriptor) || !initializationManifestMatchesDescriptor(stored, d) {
		return false
	}
	storeID, err := contract.StoreConfigurationID(contract.StoreConfiguration{Provider: m.Provider, ConstructionProfile: contract.StoreConstructionProfile,
		DomainID: m.DomainID, Region: m.Store.Region, Bucket: m.Store.Bucket, PrefixBeforeHEAD: m.Store.PrefixBeforeHEAD, ExpectedOwner: m.Store.ExpectedOwner})
	if err != nil || storeID != d.StoreID || !initializationSigningMatches(m.Authority.SigningSelector, m.Authority.Signing, d.NormalSigning) {
		return false
	}
	recipients := make(map[contract.ID]contract.RecipientRecord, len(d.Recipients))
	for _, row := range d.Recipients {
		recipients[row.RecipientID] = row
	}
	authority, ok := recipients[m.Authority.ID]
	if !ok || authority.Status != contract.CurrentRecipient || authority.DisplayName != m.Authority.DisplayName || authority.CurrentBinding == nil ||
		m.Authority.EncryptionSelector != authority.CurrentBinding.KeySelector || !initializationEncryptionMatches(m.Authority.Encryption, *authority.CurrentBinding) {
		return false
	}
	delete(recipients, m.Authority.ID)
	for _, recipient := range m.Recipients {
		row, ok := recipients[recipient.ID]
		if !ok || row.Status != contract.CurrentRecipient || row.DisplayName != recipient.DisplayName || row.CurrentBinding == nil ||
			recipient.Selector != row.CurrentBinding.KeySelector || !initializationEncryptionMatches(recipient.Encryption, *row.CurrentBinding) {
			return false
		}
		delete(recipients, recipient.ID)
	}
	if len(recipients) != 0 {
		return false
	}
	return d.Recovery == nil || initializationSigningMatches(m.Recovery.SigningSelector, m.Recovery.Signing, d.Recovery.Signing) &&
		m.Recovery.EncryptionSelector == d.Recovery.KMS.KeySelector && initializationEncryptionMatches(m.Recovery.Encryption, d.Recovery.KMS)
}

func initializationSigningMatches(selector string, key configuration.Key, binding contract.PublicSigningBinding) bool {
	return selector == binding.KeySelector && key.Selector == binding.KeySelector && bytes.Equal(key.PublicKey, binding.SPKI) && contract.Hash(key.PublicKey) == binding.Fingerprint
}

func initializationEncryptionMatches(key configuration.Key, binding contract.KMSBinding) bool {
	return key.Selector == binding.KeySelector && bytes.Equal(key.PublicKey, binding.SPKI) && contract.Hash(key.PublicKey) == binding.Fingerprint &&
		key.Binding.ID == binding.BindingID && key.Binding.Incarnation == binding.BindingIncarnationID && key.Binding.Serial == binding.BindingSerial && key.Binding.Protection == binding.ProtectionClass
}

// These relations depend only on the fixed descriptor. The allocated probe IDs,
// original request, plan and selected HEAD remain the authenticated Core
// observer's responsibility; the current editable image cannot recreate them.
func initializationManifestMatchesDescriptor(m contract.GenesisBootstrapManifestCore, d contract.GenesisDescriptorCore) bool {
	if m.RecoveryMode != d.RecoveryMode() || len(m.Signers) != 1+int(d.RecoveryMode()) || len(m.Probes) != 1+int(d.RecoveryMode()) {
		return false
	}
	normal, err := contract.NewBindingRequest(d.NormalSigning.Binding)
	if err != nil || m.NormalBindingSubjectDigest != normal.Digest() {
		return false
	}
	signing, err := contract.SigningBindingDigest(d.NormalSigning)
	if err != nil || m.Signers[0] != (contract.GenesisSignerPlanRow{TargetRole: contract.NormalSignerTarget, SigningBindingDigest: signing}) {
		return false
	}
	if d.Recovery != nil {
		basis, err := contract.NewK3BasisRequest(d.Recovery.Signing)
		if err != nil || m.K3BasisSubjectDigest != basis.Digest() {
			return false
		}
		signing, err := contract.SigningBindingDigest(d.Recovery.Signing)
		if err != nil || m.Signers[1] != (contract.GenesisSignerPlanRow{TargetRole: contract.RecoverySignerTarget, SigningBindingDigest: signing}) {
			return false
		}
	}
	bindings, err := d.BindingTable()
	if err != nil || len(m.PublicBindings) != len(bindings) {
		return false
	}
	probe := 0
	for i, binding := range bindings {
		digest, err := contract.PublicBindingDigest(binding.Binding)
		if err != nil || m.PublicBindings[i] != (contract.GenesisPublicBindingRow{SubjectKind: binding.SubjectKind, SubjectID: binding.SubjectID, BindingID: binding.Binding.BindingID, PublicBindingDigest: digest}) {
			return false
		}
		if binding.SubjectID == d.AuthorityRecipientID || binding.SubjectKind == contract.RecoveryWrapSubject {
			if probe >= len(m.Probes) {
				return false
			}
			actual := m.Probes[probe]
			if actual.SubjectKind != binding.SubjectKind || actual.SubjectID != binding.SubjectID || actual.BindingID != binding.Binding.BindingID || actual.PublicBindingDigest != digest {
				return false
			}
			probe++
		}
	}
	return probe == len(m.Probes)
}

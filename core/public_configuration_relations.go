package core

import "enkv.sh/core/contract"

func publicFieldReady[T any](c *publicConfigurationCheck, subject contract.DiagnosticSubject, field contract.DiagnosticField, value contract.PublicField[T]) bool {
	_, reported := c.seen[publicDiagnosticFieldKey{subject: subject, field: field}]
	return value.State == contract.PublicPresent && !reported
}

func (c *publicConfigurationCheck) checkRelations(v contract.PublicConfiguration) {
	store := contract.DiagnosticSubject{Kind: contract.SubjectStore}
	authority := contract.DiagnosticSubject{Kind: contract.SubjectAuthority}
	recovery := contract.DiagnosticSubject{Kind: contract.SubjectRecovery}
	storeReady := publicFieldReady(c, store, contract.FieldProvider, v.Store.Provider)
	family := func(subject contract.DiagnosticSubject, field contract.DiagnosticField, provider contract.PublicField[contract.Family]) {
		if storeReady && publicFieldReady(c, subject, field, provider) && provider.Value != v.Store.Provider.Value {
			c.add(subject, field, contract.ReasonInvalidFieldCombination, provider.SourceLocation)
		}
	}
	family(authority, contract.FieldSigningProvider, v.Authority.Signing.Provider)
	var authorityEncryption *contract.PublicEncryptionSettings
	if v.Recipients.State == contract.PublicPresent {
		for i := range v.Recipients.Value {
			row := &v.Recipients.Value[i]
			subject := contract.DiagnosticSubject{Kind: contract.SubjectRecipient, RecipientID: row.RecipientID}
			family(subject, contract.FieldEncryptionProvider, row.Encryption.Provider)
			if publicFieldReady(c, authority, contract.FieldRecipientID, v.Authority.RecipientID) && row.RecipientID == v.Authority.RecipientID.Value {
				authorityEncryption = &row.Encryption
			}
		}
	}
	if v.Recovery.Enabled.State != contract.PublicPresent || !v.Recovery.Enabled.Value {
		return
	}
	if v.Recovery.Signing != nil {
		family(recovery, contract.FieldSigningProvider, v.Recovery.Signing.Provider)
		if publicFieldReady(c, authority, contract.FieldSigningProvider, v.Authority.Signing.Provider) &&
			publicFieldReady(c, authority, contract.FieldSigningSelector, v.Authority.Signing.Selector) &&
			publicFieldReady(c, recovery, contract.FieldSigningProvider, v.Recovery.Signing.Provider) &&
			publicFieldReady(c, recovery, contract.FieldSigningSelector, v.Recovery.Signing.Selector) &&
			v.Authority.Signing.Provider.Value == v.Recovery.Signing.Provider.Value &&
			v.Authority.Signing.Selector.Value == v.Recovery.Signing.Selector.Value {
			c.add(recovery, contract.FieldSigningSelector, contract.ReasonInvalidFieldCombination, v.Recovery.Signing.Selector.SourceLocation)
		}
		if publicFieldReady(c, authority, contract.FieldSigningPublicKey, v.Authority.Signing.PublicKey) && publicFieldReady(c, authority, contract.FieldSigningFingerprint, v.Authority.Signing.Fingerprint) && publicFieldReady(c, recovery, contract.FieldSigningPublicKey, v.Recovery.Signing.PublicKey) && publicFieldReady(c, recovery, contract.FieldSigningFingerprint, v.Recovery.Signing.Fingerprint) && v.Authority.Signing.Fingerprint.Value == v.Recovery.Signing.Fingerprint.Value {
			c.add(recovery, contract.FieldSigningFingerprint, contract.ReasonInvalidFieldCombination, v.Recovery.Signing.Fingerprint.SourceLocation)
		}
	}
	if v.Recovery.Encryption == nil {
		return
	}
	family(recovery, contract.FieldEncryptionProvider, v.Recovery.Encryption.Provider)
	if authorityEncryption == nil {
		return
	}
	authorityRecipient := contract.DiagnosticSubject{Kind: contract.SubjectRecipient, RecipientID: v.Authority.RecipientID.Value}
	left, right := authorityEncryption, v.Recovery.Encryption
	if publicFieldReady(c, authorityRecipient, contract.FieldEncryptionProvider, left.Provider) &&
		publicFieldReady(c, authorityRecipient, contract.FieldEncryptionSelector, left.Selector) &&
		publicFieldReady(c, recovery, contract.FieldEncryptionProvider, right.Provider) &&
		publicFieldReady(c, recovery, contract.FieldEncryptionSelector, right.Selector) &&
		left.Provider.Value == right.Provider.Value && left.Selector.Value == right.Selector.Value {
		c.add(recovery, contract.FieldEncryptionSelector, contract.ReasonInvalidFieldCombination, right.Selector.SourceLocation)
	}
	ready := func(subject contract.DiagnosticSubject, e contract.PublicEncryptionSettings) bool {
		return publicFieldReady(c, subject, contract.FieldEncryptionProvider, e.Provider) && publicFieldReady(c, subject, contract.FieldEncryptionSelector, e.Selector) && publicFieldReady(c, subject, contract.FieldEncryptionPublicKey, e.PublicKey) && publicFieldReady(c, subject, contract.FieldEncryptionFingerprint, e.Fingerprint)
	}
	if ready(authorityRecipient, *authorityEncryption) && ready(recovery, *v.Recovery.Encryption) {
		// This pure relation reads only the actual public provider, selector and
		// fingerprint. It neither validates nor invents stored binding identities.
		if !contract.IndependentKMSBindings(contract.KMSBinding{Provider: left.Provider.Value, KeySelector: left.Selector.Value, Fingerprint: left.Fingerprint.Value}, contract.KMSBinding{Provider: right.Provider.Value, KeySelector: right.Selector.Value, Fingerprint: right.Fingerprint.Value}) {
			c.add(recovery, contract.FieldEncryptionSelector, contract.ReasonInvalidFieldCombination, right.Selector.SourceLocation)
		}
	}
}

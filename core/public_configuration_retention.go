package core

import "enkv.sh/core/contract"

func cleanPublicField[T any](c *publicConfigurationCheck, subject contract.DiagnosticSubject, field contract.DiagnosticField, value *contract.PublicField[T]) {
	if c.seen[publicDiagnosticFieldKey{subject: subject, field: field}] {
		var zero T
		value.State = contract.PublicInvalid
		value.Value = zero
	}
	if !publicSourceLocationValid(value.SourceLocation) {
		value.SourceLocation = nil
	}
}

func (c *publicConfigurationCheck) cleanSigning(subject contract.DiagnosticSubject, value *contract.PublicSigningSettings) {
	cleanPublicField(c, subject, contract.FieldSigningProvider, &value.Provider)
	cleanPublicField(c, subject, contract.FieldSigningSelector, &value.Selector)
	cleanPublicField(c, subject, contract.FieldSigningPublicKey, &value.PublicKey)
	cleanPublicField(c, subject, contract.FieldSigningFingerprint, &value.Fingerprint)
	cleanPublicField(c, subject, contract.FieldSigningRole, &value.Role)
	cleanPublicField(c, subject, contract.FieldSigningProfile, &value.Profile)
}

func (c *publicConfigurationCheck) cleanEncryption(subject contract.DiagnosticSubject, value *contract.PublicEncryptionSettings) {
	cleanPublicField(c, subject, contract.FieldEncryptionProvider, &value.Provider)
	cleanPublicField(c, subject, contract.FieldEncryptionSelector, &value.Selector)
	cleanPublicField(c, subject, contract.FieldEncryptionPublicKey, &value.PublicKey)
	cleanPublicField(c, subject, contract.FieldEncryptionFingerprint, &value.Fingerprint)
	cleanPublicField(c, subject, contract.FieldWrapProfile, &value.WrapProfile)
	cleanPublicField(c, subject, contract.FieldProtectionClass, &value.ProtectionClass)
}

func (c *publicConfigurationCheck) cleanConfiguration(value *contract.PublicConfiguration) {
	if value.Entries.State != contract.PublicPresent && value.Entries.State != contract.PublicUnavailable {
		value.Entries.State = contract.PublicInvalid
		value.Entries.Value = nil
	}
	if !publicSourceLocationValid(value.Entries.SourceLocation) {
		value.Entries.SourceLocation = nil
	}
	cleanPublicField(c, contract.DiagnosticSubject{Kind: contract.SubjectRecipient}, contract.FieldPresence, &value.Recipients)
	cleanPublicField(c, contract.DiagnosticSubject{Kind: contract.SubjectOutputBinding}, contract.FieldPresence, &value.OutputBindings)
	cleanPublicField(c, contract.DiagnosticSubject{Kind: contract.SubjectRoutingRule}, contract.FieldPresence, &value.Routing)
	cleanPublicField(c, contract.DiagnosticSubject{Kind: contract.SubjectConfiguration}, contract.FieldGroups, &value.Groups)
	if c.invalidEntries {
		value.Entries.State = contract.PublicInvalid
		value.Entries.Value = nil
	}
	if c.invalidRecipients {
		value.Recipients.State = contract.PublicInvalid
		value.Recipients.Value = nil
	}
	if c.invalidOutputs {
		value.OutputBindings.State = contract.PublicInvalid
		value.OutputBindings.Value = nil
	}
	if c.invalidRouting {
		value.Routing.State = contract.PublicInvalid
		value.Routing.Value = nil
	}
	for i := range value.Entries.Value {
		entry := &value.Entries.Value[i]
		subject := contract.DiagnosticSubject{Kind: contract.SubjectEntry, Name: entry.Name}
		cleanPublicField(c, subject, contract.FieldClass, &entry.Class)
		generatedExcluded := entry.Source.State == contract.PublicPresent && entry.Source.Value == contract.Supplied
		cleanPublicField(c, subject, contract.FieldSource, &entry.Source)
		cleanPublicField(c, subject, contract.FieldInputEncoding, &entry.InputEncoding)
		cleanPublicField(c, subject, contract.FieldOutputEncoding, &entry.OutputEncoding)
		if generatedExcluded {
			entry.Generated = nil
		}
		cleanPublicField(c, subject, contract.FieldPlainValue, &entry.PlainValue)
		cleanPublicField(c, subject, contract.FieldMemberships, &entry.Memberships)
		if entry.Class.State != contract.PublicPresent || entry.Class.Value != contract.Plain {
			entry.PlainValue.Value = nil
			if entry.PlainValue.State == contract.PublicPresent {
				entry.PlainValue.State = contract.PublicUnavailable
			}
			if !publicSourceLocationValid(entry.PlainValue.SourceLocation) {
				entry.PlainValue.SourceLocation = nil
			}
		}
		if entry.Generated != nil {
			cleanPublicField(c, subject, contract.FieldEpoch, &entry.Generated.Epoch)
			cleanPublicField(c, subject, contract.FieldResourceContract, &entry.Generated.ResourceContractID)
			cleanPublicField(c, subject, contract.FieldConfigContract, &entry.Generated.ConfigContractID)
			cleanPublicField(c, subject, contract.FieldLifecycle, &entry.Generated.LifecycleMode)
			cleanPublicField(c, subject, contract.FieldContentIntent, &entry.Generated.ContentIntent)
			cleanPublicField(c, subject, contract.FieldRetirement, &entry.Generated.Retirement)
			cleanPublicField(c, subject, contract.FieldCompletion, &entry.Generated.Completion)
		}
	}
	for i := range value.Recipients.Value {
		row := &value.Recipients.Value[i]
		subject := contract.DiagnosticSubject{Kind: contract.SubjectRecipient, RecipientID: row.RecipientID}
		cleanPublicField(c, subject, contract.FieldDisplayName, &row.DisplayName)
		c.cleanEncryption(subject, &row.Encryption)
	}
	for i := range value.OutputBindings.Value {
		binding := &value.OutputBindings.Value[i]
		cleanPublicField(c, contract.DiagnosticSubject{Kind: contract.SubjectOutputBinding, DestinationID: binding.DestinationID}, contract.FieldDestination, &binding.Destination)

		cleanPublicField(c, contract.DiagnosticSubject{Kind: contract.SubjectOutputBinding, DestinationID: binding.DestinationID}, contract.FieldTargets, &binding.Targets)
		for j := range binding.Targets.Value {
			target := &binding.Targets.Value[j]
			subject := contract.DiagnosticSubject{Kind: contract.SubjectOutputTarget, DestinationID: binding.DestinationID, Name: target.EntryName}
			cleanPublicField(c, subject, contract.FieldServiceContract, &target.ServiceContractID)
			cleanPublicField(c, subject, contract.FieldTargetContract, &target.TargetContractID)
			cleanPublicField(c, subject, contract.FieldCanonicalTarget, &target.CanonicalTarget)
			cleanPublicField(c, subject, contract.FieldConsumerLocator, &target.ConsumerLocator)
			cleanPublicField(c, subject, contract.FieldTargetData, &target.TargetData)
			cleanPublicField(c, subject, contract.FieldPayloadEncoding, &target.PayloadEncoding)
			cleanPublicField(c, subject, contract.FieldLocatorRequiresCreation, &target.LocatorRequiresCreation)
			cleanPublicField(c, subject, contract.FieldCapabilities, &target.Capabilities)
			cleanPublicField(c, subject, contract.FieldCreateValueBounds, &target.CreateValueBounds)
			cleanPublicField(c, subject, contract.FieldWriteValueBounds, &target.WriteValueBounds)
			cleanPublicField(c, subject, contract.FieldConsumerPolicy, &target.ConsumerPolicy)

		}
	}
	for i := range value.Routing.Value {
		route := &value.Routing.Value[i]
		cleanPublicField(c, contract.DiagnosticSubject{Kind: contract.SubjectRoutingRule, RoutingKey: route.Key}, contract.FieldDestinations, &route.Destinations)
	}
	cleanPublicField(c, contract.DiagnosticSubject{Kind: contract.SubjectDomain}, contract.FieldDomainID, &value.Store.DomainID)
	cleanPublicField(c, contract.DiagnosticSubject{Kind: contract.SubjectStore}, contract.FieldProvider, &value.Store.Provider)
	cleanPublicField(c, contract.DiagnosticSubject{Kind: contract.SubjectStore}, contract.FieldConstructionProfile, &value.Store.ConstructionProfile)
	cleanPublicField(c, contract.DiagnosticSubject{Kind: contract.SubjectStore}, contract.FieldRegion, &value.Store.Region)
	cleanPublicField(c, contract.DiagnosticSubject{Kind: contract.SubjectStore}, contract.FieldBucket, &value.Store.Bucket)
	cleanPublicField(c, contract.DiagnosticSubject{Kind: contract.SubjectStore}, contract.FieldPrefix, &value.Store.Prefix)
	cleanPublicField(c, contract.DiagnosticSubject{Kind: contract.SubjectStore}, contract.FieldExpectedOwner, &value.Store.ExpectedOwner)
	authority := contract.DiagnosticSubject{Kind: contract.SubjectAuthority}
	cleanPublicField(c, authority, contract.FieldRecipientID, &value.Authority.RecipientID)
	c.cleanSigning(authority, &value.Authority.Signing)
	recovery := contract.DiagnosticSubject{Kind: contract.SubjectRecovery}
	cleanPublicField(c, recovery, contract.FieldEnabled, &value.Recovery.Enabled)
	if value.Recovery.Signing != nil {
		c.cleanSigning(recovery, value.Recovery.Signing)
	}
	if value.Recovery.Encryption != nil {
		c.cleanEncryption(recovery, value.Recovery.Encryption)
	}
	if value.Recovery.Enabled.State == contract.PublicInvalid {
		value.Recovery.Signing = nil
		value.Recovery.Encryption = nil
	}
}

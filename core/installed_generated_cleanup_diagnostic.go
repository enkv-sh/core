package core

import (
	"enkv.sh/core/contract"
	"strings"
)

func cleanupDiagnosticValid(d contract.Diagnostic) bool {
	if !cleanupDiagnosticReason(d.Reason) || d.Outcome != contract.DiagnosticUnable && d.Outcome != contract.DiagnosticDifference || len(d.Path) < 1 || len(d.Path) > 2 {
		return false
	}
	if len(d.Path) == 2 && (d.Subject.Kind != contract.SubjectEntry || d.Path[0] != contract.FieldGenerated) {
		return false
	}
	for _, p := range d.Path {
		if !cleanupDiagnosticField(p) {
			return false
		}
	}
	s := d.Subject
	if !cleanupText(s.Name, contract.CryptoMaxName) || !cleanupText(s.DestinationID, contract.CryptoMaxName) {
		return false
	}
	zero := contract.PublicRoutingKey{}
	switch s.Kind {
	case contract.SubjectEntry:
		if !s.RecipientID.IsZero() || s.DestinationID != "" || s.RoutingKey != zero {
			return false
		}
	case contract.SubjectRecipient:
		if s.Name != "" || s.DestinationID != "" || s.RoutingKey != zero {
			return false
		}
	case contract.SubjectOutputBinding, contract.SubjectOutputTarget:
		if !s.RecipientID.IsZero() || s.RoutingKey != zero || s.Kind == contract.SubjectOutputBinding && s.Name != "" {
			return false
		}
	case contract.SubjectRoutingRule:
		if s.Name != "" || s.DestinationID != "" || !s.RecipientID.IsZero() {
			return false
		}
		k := s.RoutingKey
		if k != zero || len(d.Path) != 1 || d.Path[0] != contract.FieldPresence {
			if !publicRoutingKeyValid(k) || !cleanupText(k.EntryName, contract.CryptoMaxName) {
				return false
			}
		}
	case contract.SubjectDomain, contract.SubjectStore, contract.SubjectAuthority, contract.SubjectRecovery, contract.SubjectConfiguration, contract.SubjectObservation:
		if s.Name != "" || s.DestinationID != "" || !s.RecipientID.IsZero() || s.RoutingKey != zero {
			return false
		}
	default:
		return false
	}
	if v := d.SourceLocation; v != nil {
		if len(v.SourceID) == 0 || len(v.SourceID) > 64 || v.Line == 0 || v.Column == 0 {
			return false
		}
		for _, b := range []byte(v.SourceID) {
			if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-", rune(b)) {
				return false
			}
		}
	}
	return true
}
func writeCleanupDiagnostic(w *cleanupHashWriter, d contract.Diagnostic) {
	s := d.Subject
	k := s.RoutingKey
	w.text(string(s.Kind))
	w.text(s.Name)
	w.optionalID(s.RecipientID)
	w.text(s.DestinationID)
	w.u8(uint8(k.EntrySelector))
	w.text(k.EntryName)
	w.u32(uint32(len(d.Path)))
	for _, p := range d.Path {
		w.text(string(p))
	}
	w.text(string(d.Outcome))
	w.text(string(d.Reason))
	w.boolean(d.SourceLocation != nil)
	if v := d.SourceLocation; v != nil {
		w.text(v.SourceID)
		w.u64(v.Line)
		w.u64(v.Column)
	}
}

func cleanupDiagnosticField(field contract.DiagnosticField) bool {
	switch field {
	case contract.FieldCreateValueBounds, contract.FieldWriteValueBounds, contract.FieldServiceContract, contract.FieldCanonicalSettings, contract.FieldCapabilities, contract.FieldLocatorRequiresCreation, contract.FieldPresence, contract.FieldName, contract.FieldClass, contract.FieldSource, contract.FieldInputEncoding, contract.FieldOutputEncoding, contract.FieldPlainValue, contract.FieldMemberships, contract.FieldGenerated, contract.FieldEpoch, contract.FieldResourceContract, contract.FieldConfigContract, contract.FieldLifecycle, contract.FieldContentIntent, contract.FieldRetirement, contract.FieldCompletion, contract.FieldDisplayName, contract.FieldDestination, contract.FieldGroups, contract.FieldEncryptionProvider, contract.FieldEncryptionSelector, contract.FieldEncryptionPublicKey, contract.FieldEncryptionFingerprint, contract.FieldWrapProfile, contract.FieldProtectionClass, contract.FieldTargets, contract.FieldProvider, contract.FieldCanonicalTarget, contract.FieldConsumerLocator, contract.FieldTargetContract, contract.FieldTargetData, contract.FieldPayloadEncoding, contract.FieldConsumerPolicy, contract.FieldDestinations, contract.FieldDomainID, contract.FieldConstructionProfile, contract.FieldRegion, contract.FieldBucket, contract.FieldPrefix, contract.FieldExpectedOwner, contract.FieldRecipientID, contract.FieldSigningProvider, contract.FieldSigningSelector, contract.FieldSigningPublicKey, contract.FieldSigningFingerprint, contract.FieldSigningRole, contract.FieldSigningProfile, contract.FieldEnabled:
		return true
	}
	return false
}
func cleanupDiagnosticReason(reason contract.DiagnosticReason) bool {
	switch reason {
	case contract.ReasonExpectedEntryAbsent, contract.ReasonObservedEntryAbsent, contract.ReasonExpectedSettingAbsent, contract.ReasonObservedSettingAbsent, contract.ReasonFieldDiffers, contract.ReasonSetDiffers, contract.ReasonBytesDiffer, contract.ReasonPublicFactUnavailable, contract.ReasonInvalidInput, contract.ReasonMissingRequiredField, contract.ReasonDuplicateKey, contract.ReasonDuplicateMember, contract.ReasonUnresolvedReference, contract.ReasonInvalidUTF8, contract.ReasonLimitExceeded, contract.ReasonInvalidFieldCombination, contract.ReasonTrustBasisInvalid, contract.ReasonDomainBasisInvalid, contract.ReasonStoreBasisInvalid, contract.ReasonExpired, contract.ReasonCancelled, contract.ReasonUnsupportedSchema, contract.ReasonUnsupportedProfile, contract.ReasonHeadInvalid, contract.ReasonProofInvalid, contract.ReasonSelectedObjectInvalid, contract.ReasonSelectedRelationInvalid, contract.ReasonEvidenceUnavailable, contract.ReasonSelectedObjectUnavailable, contract.ReasonReadContention, contract.ReasonDiagnosticsIncomplete, contract.ReasonTargetAbsent, contract.ReasonEntryAbsent, contract.ReasonDuplicateEntry, contract.ReasonTargetNotAuthorized, contract.ReasonLocatorUnusable:
		return true
	}
	return false
}

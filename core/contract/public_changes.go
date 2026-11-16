package contract

// ComparisonFieldValueType owns the closed public field/type correspondence.
// No current comparison field admits the reserved nullable scalar arm.
func ComparisonFieldValueType(kind DiagnosticSubjectKind, path []DiagnosticField) ComparisonValueType {
	if len(path) == 2 {
		if kind != SubjectEntry || path[0] != FieldGenerated {
			return ""
		}
		switch path[1] {
		case FieldEpoch, FieldLifecycle, FieldRetirement, FieldCompletion:
			return ComparisonTypeUint
		case FieldConfigContract, FieldResourceContract:
			return ComparisonTypeID
		case FieldContentIntent:
			return ComparisonTypeBytes
		}
		return ""
	}
	if len(path) != 1 {
		return ""
	}
	field := path[0]
	switch kind {
	case SubjectEntry:
		switch field {
		case FieldPresence:
			return ComparisonTypeBoolean
		case FieldName:
			return ComparisonTypeText
		case FieldClass, FieldSource, FieldInputEncoding, FieldOutputEncoding:
			return ComparisonTypeUint
		case FieldPlainValue:
			return ComparisonTypeBytes
		case FieldMemberships:
			return ComparisonTypeIDSet
		}
	case SubjectRecipient:
		switch field {
		case FieldPresence:
			return ComparisonTypeBoolean
		case FieldDisplayName:
			return ComparisonTypeText
		}
		return comparisonEncryptionFieldType(field)
	case SubjectOutputBinding:
		switch field {
		case FieldPresence:
			return ComparisonTypeBoolean
		case FieldDestination:
			return ComparisonTypeDestination
		case FieldTargets:
			return ComparisonTypeTextSet
		}
	case SubjectOutputTarget:
		switch field {
		case FieldPresence, FieldLocatorRequiresCreation:
			return ComparisonTypeBoolean
		case FieldServiceContract, FieldTargetContract, FieldCanonicalTarget, FieldConsumerLocator:
			return ComparisonTypeText
		case FieldTargetData:
			return ComparisonTypeBytes
		case FieldPayloadEncoding, FieldCapabilities:
			return ComparisonTypeUint
		case FieldCreateValueBounds, FieldWriteValueBounds:
			return ComparisonTypeBounds
		case FieldConsumerPolicy:
			return ComparisonTypePolicy
		}
	case SubjectRoutingRule:
		switch field {
		case FieldPresence:
			return ComparisonTypeBoolean
		case FieldDestinations:
			return ComparisonTypeTextSet
		}
	case SubjectDomain:
		if field == FieldDomainID {
			return ComparisonTypeID
		}
	case SubjectStore:
		switch field {
		case FieldProvider, FieldConstructionProfile:
			return ComparisonTypeUint
		case FieldRegion, FieldBucket, FieldPrefix, FieldExpectedOwner:
			return ComparisonTypeText
		}
	case SubjectAuthority:
		if field == FieldRecipientID {
			return ComparisonTypeID
		}
		return comparisonSigningFieldType(field)
	case SubjectRecovery:
		if field == FieldEnabled {
			return ComparisonTypeBoolean
		}
		if valueType := comparisonSigningFieldType(field); valueType != "" {
			return valueType
		}
		return comparisonEncryptionFieldType(field)
	case SubjectConfiguration:
		if field == FieldGroups {
			return ComparisonTypeGroups
		}
	}
	return ""
}

func comparisonEncryptionFieldType(field DiagnosticField) ComparisonValueType {
	switch field {
	case FieldEncryptionProvider, FieldWrapProfile, FieldProtectionClass:
		return ComparisonTypeUint
	case FieldEncryptionSelector:
		return ComparisonTypeText
	case FieldEncryptionPublicKey:
		return ComparisonTypeBytes
	case FieldEncryptionFingerprint:
		return ComparisonTypeID
	}
	return ""
}

func comparisonSigningFieldType(field DiagnosticField) ComparisonValueType {
	switch field {
	case FieldSigningProvider, FieldSigningRole, FieldSigningProfile:
		return ComparisonTypeUint
	case FieldSigningSelector:
		return ComparisonTypeText
	case FieldSigningPublicKey:
		return ComparisonTypeBytes
	case FieldSigningFingerprint:
		return ComparisonTypeID
	}
	return ""
}
